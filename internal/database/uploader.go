// Package database — uploader.go.
//
// S3-compatible multipart uploader used by export_dump. Wraps the AWS
// SDK v2 S3 client with an io.WriteCloser surface so the encrypter
// upstream can stream straight in. Internally:
//
//   - 8-MiB part buffer (well above S3's 5-MiB minimum, low enough to
//     keep RAM usage bounded under any plausible dump size)
//   - On every full part we issue UploadPart, record the ETag, and reset.
//   - On Close() we flush the trailing partial part and call
//     CompleteMultipartUpload with the part list in order.
//   - On any error during streaming, callers are expected to invoke
//     Abort(); the orchestrator does this in its defer.
//   - Progress callbacks fire after each successful part upload, with
//     the running total of bytes transferred.
//
// The same code path serves AWS S3, MinIO, Cloudflare R2, and any other
// S3-API-compatible store. MinIO and on-prem deployments require
// path-style addressing and a custom endpoint; AWS native is virtual-
// hosted style with no endpoint override.
//
// We intentionally bypass the SDK's `feature/s3/manager.Uploader`. That
// helper buffers the entire stream to disk by default and we want
// streaming-only semantics with hand-driven progress reporting.
package database

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

const (
	// uploaderPartSize is the in-memory buffer per part. AWS S3 requires
	// 5 MiB minimum (except for the final part); 8 MiB rounds up nicely
	// and keeps the part count manageable for multi-GB dumps (max 10000
	// parts in a single multipart upload → 80 GiB before we need to grow).
	uploaderPartSize = 8 * 1024 * 1024
)

// ChunkUploader is an io.WriteCloser that streams its input as an S3
// multipart upload. NOT safe for concurrent use; one writer per upload.
type ChunkUploader struct {
	ctx        context.Context
	client     *s3.Client
	bucket     string
	key        string
	uploadID   string
	onProgress func(uploadedBytes uint64)

	mu          sync.Mutex
	buf         *bytes.Buffer // current in-flight part accumulator
	partNumber  int32
	parts       []types.CompletedPart
	uploaded    uint64
	closed      bool
	aborted     bool
	completeErr error // sticky error from last part upload, propagated by Close
}

// NewChunkUploader initializes the multipart upload (one CreateMultipart
// call) and returns a writer ready to stream bytes into. The caller MUST
// invoke Close() to finalize; if Close() is not called, the multipart
// upload is leaked on the destination bucket and S3 will silently keep
// charging for the staged parts.
func NewChunkUploader(
	ctx context.Context,
	dest *DestinationDescriptor,
	objectKey string,
	onProgress func(uploadedBytes uint64),
) (*ChunkUploader, error) {
	if dest == nil {
		return nil, errors.New("uploader: nil destination")
	}
	if dest.Bucket == "" {
		return nil, errors.New("uploader: empty bucket")
	}
	if objectKey == "" {
		return nil, errors.New("uploader: empty object key")
	}
	if dest.Region == "" {
		return nil, errors.New("uploader: empty region")
	}
	if dest.AccessKeyID == "" || dest.SecretAccessKey == "" {
		return nil, errors.New("uploader: missing access credentials")
	}

	cfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(dest.Region),
		awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(dest.AccessKeyID, dest.SecretAccessKey, ""),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("uploader: load aws config: %w", err)
	}

	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		// MinIO / R2 / on-prem all require path-style addressing because
		// they don't issue per-bucket DNS names. AWS native works either
		// way but path-style is being deprecated, so we only flip when
		// the caller asks.
		if dest.UsePathStyle {
			o.UsePathStyle = true
		}
		if dest.Endpoint != "" {
			endpoint := dest.Endpoint
			o.BaseEndpoint = &endpoint
		}
	})

	out, err := client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
		Bucket: aws.String(dest.Bucket),
		Key:    aws.String(objectKey),
		// ContentType is intentionally a binary blob: we encrypted the
		// dump with our own format, so consumers must not treat it as a
		// dump or a gzip — it's opaque ciphertext until decrypted.
		ContentType: aws.String("application/octet-stream"),
	})
	if err != nil {
		return nil, fmt.Errorf("uploader: create multipart: %w", err)
	}

	return &ChunkUploader{
		ctx:        ctx,
		client:     client,
		bucket:     dest.Bucket,
		key:        objectKey,
		uploadID:   aws.ToString(out.UploadId),
		onProgress: onProgress,
		buf:        bytes.NewBuffer(make([]byte, 0, uploaderPartSize)),
		partNumber: 0,
	}, nil
}

// Write buffers p into the current part. When the buffer reaches
// uploaderPartSize, one part is uploaded synchronously and the buffer
// reset. Returns len(p) on success or the underlying upload error.
func (u *ChunkUploader) Write(p []byte) (int, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		return 0, errors.New("uploader: write on closed uploader")
	}
	if u.completeErr != nil {
		return 0, u.completeErr
	}
	written := 0
	for len(p) > 0 {
		room := uploaderPartSize - u.buf.Len()
		take := len(p)
		if take > room {
			take = room
		}
		u.buf.Write(p[:take])
		p = p[take:]
		written += take
		if u.buf.Len() >= uploaderPartSize {
			if err := u.uploadCurrentPartLocked(); err != nil {
				u.completeErr = err
				return written, err
			}
		}
	}
	return written, nil
}

// Close flushes the trailing partial part and finalizes the multipart
// upload. If the upload was aborted (via Abort()) Close is a no-op.
// On any error, Close attempts to abort the staged multipart upload to
// avoid leaving orphaned parts in the bucket.
func (u *ChunkUploader) Close() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		return nil
	}
	u.closed = true
	if u.aborted {
		return nil
	}
	if u.completeErr != nil {
		_ = u.abortLocked()
		return u.completeErr
	}

	// Flush the tail. S3 allows the LAST part to be < 5 MiB; we don't need
	// to special-case it, just upload whatever is left.
	if u.buf.Len() > 0 {
		if err := u.uploadCurrentPartLocked(); err != nil {
			_ = u.abortLocked()
			return err
		}
	}
	if len(u.parts) == 0 {
		// Zero-byte object: S3 multipart requires at least one part.
		// Upload a single empty part so the object materializes. This is
		// rare in practice (the encrypter always emits at least the GCM
		// tag for any non-empty dump) but worth handling cleanly.
		if err := u.uploadEmptyFirstPartLocked(); err != nil {
			_ = u.abortLocked()
			return err
		}
	}

	// Sort parts by number — AWS rejects out-of-order CompletedPart
	// arrays. We always append in order so this is defensive only.
	sort.Slice(u.parts, func(i, j int) bool {
		return aws.ToInt32(u.parts[i].PartNumber) < aws.ToInt32(u.parts[j].PartNumber)
	})

	_, err := u.client.CompleteMultipartUpload(u.ctx, &s3.CompleteMultipartUploadInput{
		Bucket:          aws.String(u.bucket),
		Key:             aws.String(u.key),
		UploadId:        aws.String(u.uploadID),
		MultipartUpload: &types.CompletedMultipartUpload{Parts: u.parts},
	})
	if err != nil {
		_ = u.abortLocked()
		return fmt.Errorf("uploader: complete multipart: %w", err)
	}
	return nil
}

// Abort tears down the staged multipart upload without finalizing.
// Idempotent; safe to call from a defer in the orchestrator.
func (u *ChunkUploader) Abort() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.abortLocked()
}

// Uploaded returns the running total of bytes successfully shipped to
// the destination (i.e. summed over all UploadPart calls that returned
// 200). Bytes still buffered in the current part are NOT counted.
func (u *ChunkUploader) Uploaded() uint64 {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.uploaded
}

// uploadCurrentPartLocked ships u.buf as the next part. Caller must hold u.mu.
func (u *ChunkUploader) uploadCurrentPartLocked() error {
	u.partNumber++
	partNum := u.partNumber
	body := bytes.NewReader(u.buf.Bytes())
	partLen := u.buf.Len()

	out, err := u.client.UploadPart(u.ctx, &s3.UploadPartInput{
		Bucket:     aws.String(u.bucket),
		Key:        aws.String(u.key),
		UploadId:   aws.String(u.uploadID),
		PartNumber: aws.Int32(partNum),
		Body:       body,
	})
	if err != nil {
		return fmt.Errorf("uploader: upload part %d: %w", partNum, err)
	}
	u.parts = append(u.parts, types.CompletedPart{
		ETag:       out.ETag,
		PartNumber: aws.Int32(partNum),
	})
	u.uploaded += uint64(partLen)

	// Reset the buffer to the same capacity for reuse. bytes.Buffer.Reset
	// is O(1) and preserves the underlying array.
	u.buf.Reset()

	if u.onProgress != nil {
		// Capture under the lock so the value is consistent at callback time.
		uploaded := u.uploaded
		// Release the lock for the callback so a slow callback does not
		// block subsequent Writes. The orchestrator's progress emitter
		// is designed to be cheap, but this protects against future
		// changes that add I/O to the callback.
		u.mu.Unlock()
		u.onProgress(uploaded)
		u.mu.Lock()
	}
	return nil
}

// uploadEmptyFirstPartLocked handles the zero-byte stream edge case.
func (u *ChunkUploader) uploadEmptyFirstPartLocked() error {
	u.partNumber++
	partNum := u.partNumber
	out, err := u.client.UploadPart(u.ctx, &s3.UploadPartInput{
		Bucket:     aws.String(u.bucket),
		Key:        aws.String(u.key),
		UploadId:   aws.String(u.uploadID),
		PartNumber: aws.Int32(partNum),
		Body:       bytes.NewReader(nil),
	})
	if err != nil {
		return fmt.Errorf("uploader: upload empty part: %w", err)
	}
	u.parts = append(u.parts, types.CompletedPart{
		ETag:       out.ETag,
		PartNumber: aws.Int32(partNum),
	})
	return nil
}

// abortLocked issues AbortMultipartUpload. Caller must hold u.mu.
func (u *ChunkUploader) abortLocked() error {
	if u.aborted {
		return nil
	}
	u.aborted = true
	// Use a fresh context for the abort: if the upstream ctx is canceled
	// (which is the most common reason we're aborting in the first place)
	// we still want the abort RPC to land on the destination, otherwise
	// the staged parts linger forever.
	abortCtx, cancel := context.WithTimeout(context.Background(), abortTimeout)
	defer cancel()
	_, err := u.client.AbortMultipartUpload(abortCtx, &s3.AbortMultipartUploadInput{
		Bucket:   aws.String(u.bucket),
		Key:      aws.String(u.key),
		UploadId: aws.String(u.uploadID),
	})
	if err != nil {
		return fmt.Errorf("uploader: abort multipart: %w", err)
	}
	return nil
}
