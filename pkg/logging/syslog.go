//go:build linux

// Copyright (c) Facebook, Inc. and its affiliates.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package logging

import (
	"context"
	"fmt"
	"log/slog"
	"log/syslog"
	"strings"
	"sync"
)

// SyslogWriter abstracts the level-specific write methods of *syslog.Writer.
// Exported for mock generation via go.uber.org/mock.
type SyslogWriter interface {
	Debug(m string) error
	Info(m string) error
	Warning(m string) error
	Err(m string) error
}

// groupedAttr pairs an slog.Attr with the group prefix that was active
// when the attr was added. This ensures WithGroup only qualifies keys
// of subsequent attrs, per the slog.Handler contract.
type groupedAttr struct {
	group string
	attr  slog.Attr
}

// handler implements slog.Handler backed by a SyslogWriter.
// Each record is formatted as: <msg> key1=val1 key2=val2 ...
type handler struct {
	w     SyslogWriter
	mu    sync.Mutex
	attrs []groupedAttr
	group string
}

func (h *handler) Enabled(_ context.Context, _ slog.Level) bool {
	return true
}

func (h *handler) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder
	b.WriteString(r.Message)

	writeAttr := func(group string, a slog.Attr) {
		if a.Equal(slog.Attr{}) {
			return
		}
		key := a.Key
		if group != "" {
			key = group + "." + key
		}
		val := a.Value.Resolve().String()
		if strings.ContainsAny(val, " \t\"") {
			fmt.Fprintf(&b, " %s=%q", key, val)
		} else {
			fmt.Fprintf(&b, " %s=%s", key, val)
		}
	}

	for _, ga := range h.attrs {
		writeAttr(ga.group, ga.attr)
	}
	r.Attrs(func(a slog.Attr) bool {
		writeAttr(h.group, a)
		return true
	})

	msg := Sanitize(b.String())

	h.mu.Lock()
	defer h.mu.Unlock()

	switch {
	case r.Level >= slog.LevelError:
		return h.w.Err(msg)
	case r.Level >= slog.LevelWarn:
		return h.w.Warning(msg)
	case r.Level >= slog.LevelInfo:
		return h.w.Info(msg)
	default:
		return h.w.Debug(msg)
	}
}

func (h *handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	newAttrs := make([]groupedAttr, len(h.attrs), len(h.attrs)+len(attrs))
	copy(newAttrs, h.attrs)
	for _, a := range attrs {
		newAttrs = append(newAttrs, groupedAttr{group: h.group, attr: a})
	}
	return &handler{
		w:     h.w,
		attrs: newAttrs,
		group: h.group,
	}
}

func (h *handler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	newGroup := name
	if h.group != "" {
		newGroup = h.group + "." + name
	}
	newAttrs := make([]groupedAttr, len(h.attrs))
	copy(newAttrs, h.attrs)
	return &handler{
		w:     h.w,
		attrs: newAttrs,
		group: newGroup,
	}
}

// Sanitize replaces newlines and NULs that would break syslog single-line framing.
// Stdlib syslog.Writer does not strip embedded newlines from messages,
// so we sanitize to keep LIDE replicator regex compatibility.
func Sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '\n', '\r', 0:
			return ' '
		default:
			return r
		}
	}, s)
}

// NewHandler creates a slog.Handler backed by the given SyslogWriter.
// Useful for testing with a mock writer.
func NewHandler(w SyslogWriter) slog.Handler {
	return &handler{w: w}
}

// NewSyslogHandler returns a slog.Handler that writes to local syslog with the
// given tag. On any failure, returns a no-op handler — never writes to stderr.
func NewSyslogHandler(tag string) slog.Handler {
	w, err := syslog.New(syslog.LOG_DAEMON|syslog.LOG_INFO, tag)
	if err != nil {
		return NoopHandler{}
	}
	return &handler{w: w}
}
