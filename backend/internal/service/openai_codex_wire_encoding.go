package service

import (
	"bytes"
	"fmt"
	"io"
	"net/http"

	"github.com/klauspost/compress/zstd"
)

// 真机 codex-cli 0.167.0 的推理面固定以 `content-encoding: zstd` 发送压缩体
// （抓包实测，帧头恒为 28 b5 2f fd 00 58）。未压缩的出站请求体是一个直接的
// 形态差异：真机 content-length 约为明文的三分之一，且必定带该头。
//
// 帧头对齐：klauspost 默认输出 FHD=0x80（FCS 存在、单 segment）与 512KB 窗口；
// 真机是 FHD=0x00（无 FCS、无 checksum、非 singleSegment）+ windowDesc=0x58
// （windowLog=21 = 2MB）。窗口放大不改变历史 offset 的合法性，因此可原地换头：
// 只要解码端允许 2MB 窗口，帧仍完全有效。

const codexWireContentEncoding = "zstd"

// codexZstdMagic 是 zstd 帧起始标识。
var codexZstdMagic = []byte{0x28, 0xb5, 0x2f, 0xfd}

// codexZstdEncoder 全局复用：编码器内部有状态但 EncodeAll 并发安全。
var codexZstdEncoder = func() *zstd.Encoder {
	enc, err := zstd.NewWriter(nil,
		zstd.WithEncoderConcurrency(1),
		zstd.WithSingleSegment(false),
		zstd.WithWindowSize(2<<20),
		zstd.WithEncoderCRC(false),
		zstd.WithEncoderLevel(zstd.SpeedDefault),
	)
	if err != nil {
		return nil
	}
	return enc
}()

// rewriteCodexZstdFrameHeader 把编码器的帧头改写成真机形态。
func rewriteCodexZstdFrameHeader(frame []byte) ([]byte, error) {
	if len(frame) < 6 || !bytes.Equal(frame[:4], codexZstdMagic) {
		return nil, fmt.Errorf("not a zstd frame")
	}
	fhd := frame[4]
	off := 6 // magic + FHD + window descriptor
	if fhd&0x04 != 0 {
		off += 4 // dictionary id
	}
	switch fhd >> 6 {
	case 1:
		off += 2
	case 2:
		off += 4
	case 3:
		off += 8
	}
	if off > len(frame) {
		return nil, fmt.Errorf("truncated zstd frame header")
	}
	out := make([]byte, 0, len(frame)-off+6)
	out = append(out, codexZstdMagic...)
	out = append(out, 0x00, 0x58)
	return append(out, frame[off:]...), nil
}

// compressCodexBody 按真机形态压缩请求体。
func compressCodexBody(body []byte) ([]byte, error) {
	if codexZstdEncoder == nil {
		return nil, fmt.Errorf("zstd encoder unavailable")
	}
	frame := codexZstdEncoder.EncodeAll(body, nil)
	return rewriteCodexZstdFrameHeader(frame)
}

// applyCodexWireCompression 就地把出站请求体替换为 zstd 压缩体并声明编码。
// 必须在所有会改写 req.Body 的步骤（含 lite 兼容层）之后调用。
//
// 只读 body 已被上游接受的路径才压缩：API-key 直连的第三方兼容网关未必解 zstd，
// 因此限定 Codex 内网接口。compact 走 unary JSON，同样压缩（真机同源）。
func applyCodexWireCompression(req *http.Request) error {
	if req == nil || req.Body == nil {
		return nil
	}
	// 优先用 GetBody（不消耗 req.Body）；构造器未设时回退读 Body，随后整段替换。
	var plain io.ReadCloser
	if req.GetBody != nil {
		var err error
		if plain, err = req.GetBody(); err != nil {
			return err
		}
	} else {
		plain = req.Body
	}
	defer plain.Close()

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(plain); err != nil {
		return err
	}
	compressed, err := compressCodexBody(buf.Bytes())
	if err != nil {
		return err
	}

	req.Body = newCodexBytesReadCloser(compressed)
	saved := compressed
	req.GetBody = func() (io.ReadCloser, error) { return newCodexBytesReadCloser(saved), nil }
	req.ContentLength = int64(len(compressed))
	req.Header.Set("content-encoding", codexWireContentEncoding)
	// 压缩后长度变化，Content-Length 头随之重算（Transfer-Encoding 由 Transport 决定）。
	req.Header.Del("content-length")
	return nil
}

// codexBytesReadCloser 让 req.Body 保持可重复读取，配合 GetBody 支撑重试。
type codexBytesReadCloser struct{ *bytes.Reader }

func (codexBytesReadCloser) Close() error { return nil }

func newCodexBytesReadCloser(b []byte) *codexBytesReadCloser {
	return &codexBytesReadCloser{bytes.NewReader(b)}
}
