// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package bodyprocessors

import (
	"errors"
	"fmt"
	"io"
	"maps"
	"mime"
	"mime/multipart"
	"os"
	"slices"
	"strings"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/collections"
	"github.com/corazawaf/coraza/v3/internal/environment"
)

// MaxHeadersPerPart is the number of headers a legitimate multipart part is
// expected to carry: Content-Disposition, Content-Type and
// Content-Transfer-Encoding, plus margin for the uncommon ones a client may
// add. It scales the argument limit into the budget MULTIPART_PART_HEADERS
// gets, keeping the budget out of reach of ordinary forms while a header flood,
// which Go's multipart reader admits up to 10000 of per part, still exhausts
// it.
const MaxHeadersPerPart = 8

type multipartBodyProcessor struct{}

func (mbp *multipartBodyProcessor) ProcessRequest(reader io.Reader, v plugintypes.TransactionVariables, options plugintypes.BodyProcessorOptions) error {
	mimeType := options.Mime
	storagePath := options.StoragePath
	mediaType, params, err := mime.ParseMediaType(mimeType)
	if err != nil {
		v.MultipartStrictError().(*collections.Single).Set("1")
		return err
	}
	if !strings.HasPrefix(mediaType, "multipart/") {
		return errors.New("not a multipart body")
	}
	mr := multipart.NewReader(reader, params["boundary"])
	totalSize := int64(0)
	filesCol := v.Files()
	filesTmpNamesCol := v.FilesTmpNames()
	fileSizesCol := v.FilesSizes()
	postCol := v.ArgsPost()
	filesCombinedSizeCol := v.FilesCombinedSize()
	filesNamesCol := v.FilesNames()
	headersNames := v.MultipartPartHeaders()
	// The argument budget covers the members that carry attacker-supplied
	// values, one per part: a field part costs its ARGS_POST value, and a file
	// part costs one member for FILES, FILES_NAMES, FILES_SIZES and
	// FILES_TMP_NAMES together, which are four views of the same part whose
	// combined size SecRequestBodyLimit already bounds. ModSecurity charges file
	// parts nothing at all. The budget is checked before reading a part's body,
	// so over-budget parts are never buffered and never create temp files.
	// Part-header count is attacker-controlled and independent of argument
	// content, so MULTIPART_PART_HEADERS gets its own separate budget: the
	// argument limit scaled by MaxHeadersPerPart, so a form whose parts fit the
	// argument budget cannot reach it. Exhausting it stops recording further
	// headers but never aborts the parse, so a part-header flood cannot empty
	// the argument collections; the parse then reports ErrArgumentsLimit so the
	// truncation is visible to the rules.
	limit := options.ArgumentLimit
	headerLimit := scaleArgumentLimit(limit, MaxHeadersPerPart)
	members := 0
	headerMembers := 0
	headersOverLimit := false
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			v.MultipartStrictError().(*collections.Single).Set("1")
			return err
		}
		partName := p.FormName()
		// Sorted so that the headers a part keeps when the budget runs out are a
		// stable prefix rather than whichever ones the map happened to yield.
		for _, key := range slices.Sorted(maps.Keys(p.Header)) {
			for _, value := range p.Header[key] {
				if limit > 0 && headerMembers >= headerLimit {
					headersOverLimit = true
					break
				}
				headersNames.Add(partName, fmt.Sprintf("%s: %s", key, value))
				headerMembers++
			}
		}
		if limit > 0 && members >= limit {
			return ErrArgumentsLimit
		}
		members++
		// if is a file
		filename := originFileName(p)
		if filename != "" {
			var size int64
			seenUnexpectedEOF := false
			if environment.HasAccessToFS {
				// Only copy file to temp when not running in TinyGo
				temp, err := os.CreateTemp(storagePath, "crzmp*")
				if err != nil {
					v.MultipartStrictError().(*collections.Single).Set("1")
					return err
				}
				sz, err := io.Copy(temp, p)
				if cerr := temp.Close(); cerr != nil && err == nil {
					err = cerr
				}
				// Registered before any error return so that the transaction
				// cleanup, which walks FILES_TMP_NAMES, still removes the file.
				filesTmpNamesCol.Add("", temp.Name())
				if err != nil {
					if !errors.Is(err, io.ErrUnexpectedEOF) {
						v.MultipartStrictError().(*collections.Single).Set("1")
						return err
					}
					seenUnexpectedEOF = true
				}
				size = sz
			} else {
				sz, err := io.Copy(io.Discard, p)
				if err != nil {
					if !errors.Is(err, io.ErrUnexpectedEOF) {
						v.MultipartStrictError().(*collections.Single).Set("1")
						return err
					}
					seenUnexpectedEOF = true
				}
				size = sz
			}
			totalSize += size
			filesCol.Add("", filename)
			fileSizesCol.SetIndex(filename, 0, fmt.Sprintf("%d", size))
			filesNamesCol.Add("", p.FormName())
			filesCombinedSizeCol.(*collections.Single).Set(fmt.Sprintf("%d", totalSize))
			if seenUnexpectedEOF {
				break
			}
		} else {
			// if is a field
			data, err := io.ReadAll(p)
			if err != nil {
				if !errors.Is(err, io.ErrUnexpectedEOF) {
					v.MultipartStrictError().(*collections.Single).Set("1")
					return err
				}
			}
			totalSize += int64(len(data))
			postCol.Add(p.FormName(), string(data))
			filesCombinedSizeCol.(*collections.Single).Set(fmt.Sprintf("%d", totalSize))
			if errors.Is(err, io.ErrUnexpectedEOF) {
				break
			}
		}
	}
	if headersOverLimit {
		return ErrArgumentsLimit
	}
	return nil
}

func (mbp *multipartBodyProcessor) ProcessResponse(_ io.Reader, _ plugintypes.TransactionVariables, options plugintypes.BodyProcessorOptions) error {
	return nil
}

var (
	_ plugintypes.BodyProcessor = (*multipartBodyProcessor)(nil)
)

// OriginFileName returns the filename parameter of the Part's Content-Disposition header.
// This function is based on (multipart.Part).parseContentDisposition,
// See https://go.googlesource.com/go/+/refs/tags/go1.17.9/src/mime/multipart/multipart.go#87
// for the current implementation and also notice this function hasn't change since go1.4, as in
// https://go.googlesource.com/go/+/refs/tags/go1.4/src/mime/multipart/multipart.go#75
func originFileName(p *multipart.Part) string {
	v := p.Header.Get("Content-Disposition")
	_, dispositionParams, err := mime.ParseMediaType(v)
	if err != nil {
		return ""
	}

	return dispositionParams["filename"]
}

func init() {
	RegisterBodyProcessor("multipart", func() plugintypes.BodyProcessor {
		return &multipartBodyProcessor{}
	})
}
