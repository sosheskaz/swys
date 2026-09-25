package help

import "errors"

var (
	// ErrGuideOperationalFlag identifies operational I/O flags supplied to a guide command.
	ErrGuideOperationalFlag = errors.New("guide command does not accept operational I/O flags")
	// ErrInvalidPager identifies an invalid PAGER command.
	ErrInvalidPager             = errors.New("invalid PAGER")
	errGuideNotFound            = errors.New("embedded guide not found")
	errGuidePath                = errors.New("invalid guide path")
	errEmbeddedGuide            = errors.New("invalid embedded guide")
	errInvalidGuideWidth        = errors.New("invalid guide layout width")
	errUnsupportedGuideBlock    = errors.New("unsupported guide block")
	errUnsupportedGuideMarkdown = errors.New("unsupported guide Markdown")
)
