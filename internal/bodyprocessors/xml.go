// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package bodyprocessors

import (
	"encoding/xml"
	"errors"
	"io"
	"strings"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// MaxNodesPerArgument is the number of REQUEST_XML members a document spends on
// the information a form carries in a single argument: a field becomes an
// element with a text node plus the attributes that type or namespace it, and
// the records holding those fields sit inside envelope, header and list
// elements that contribute members of their own. It scales the argument limit
// into the budget REQUEST_XML gets, so documents of a few thousand nodes parse
// whole under a limit tuned for form fields while a node flood still exhausts
// it. ModSecurity charges XML nothing at all: it ignores attributes and adds
// text nodes only under SecParseXmlIntoArgs, which is off by default. Coraza
// always populates REQUEST_XML, so the budget is what bounds the collection.
const MaxNodesPerArgument = 16

type xmlBodyProcessor struct {
}

func (*xmlBodyProcessor) ProcessRequest(reader io.Reader, v plugintypes.TransactionVariables, options plugintypes.BodyProcessorOptions) error {
	values, contents, err := readXML(reader, scaleArgumentLimit(options.ArgumentLimit, MaxNodesPerArgument))
	if err != nil && !errors.Is(err, ErrArgumentsLimit) {
		return err
	}
	col := v.RequestXML()
	col.Set("//@*", values)
	col.Set("/*", contents)
	return err
}

func (*xmlBodyProcessor) ProcessResponse(reader io.Reader, v plugintypes.TransactionVariables, options plugintypes.BodyProcessorOptions) error {
	return nil
}

// readXML extracts attribute values and element contents from an XML document.
// Attributes and contents share a single budget of limit members (<= 0 means
// unlimited); when it is exhausted, decoding stops and ErrArgumentsLimit is
// returned along with the members collected so far.
func readXML(reader io.Reader, limit int) ([]string, []string, error) {
	var attrs []string
	var content []string
	dec := xml.NewDecoder(reader)
	dec.Strict = false
	dec.AutoClose = xml.HTMLAutoClose
	dec.Entity = xml.HTMLEntity
	for {
		token, err := dec.Token()
		if err != nil && err != io.EOF && !isUnexpectedEOFXMLSyntaxError(err) {
			return nil, nil, err
		}
		if token == nil {
			break
		}
		switch tok := token.(type) {
		case xml.StartElement:
			for _, attr := range tok.Attr {
				if limit > 0 && len(attrs)+len(content) >= limit {
					return attrs, content, ErrArgumentsLimit
				}
				attrs = append(attrs, attr.Value)
			}
		case xml.CharData:
			if c := strings.TrimSpace(string(tok)); c != "" {
				if limit > 0 && len(attrs)+len(content) >= limit {
					return attrs, content, ErrArgumentsLimit
				}
				content = append(content, c)
			}
		}
	}
	return attrs, content, nil
}

func isUnexpectedEOFXMLSyntaxError(err error) bool {
	var serr *xml.SyntaxError
	return errors.As(err, &serr) && serr.Msg == "unexpected EOF"
}

var (
	_ plugintypes.BodyProcessor = &xmlBodyProcessor{}
)

func init() {
	RegisterBodyProcessor("xml", func() plugintypes.BodyProcessor {
		return &xmlBodyProcessor{}
	})
}
