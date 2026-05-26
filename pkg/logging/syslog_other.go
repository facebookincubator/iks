//go:build !linux

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

import "log/slog"

// NewSyslogHandler on non-Linux platforms always returns a no-op handler.
// The syslog package is unavailable outside Linux/Unix.
func NewSyslogHandler(_ string) slog.Handler {
	return NoopHandler{}
}

// NewHandler on non-Linux platforms always returns a no-op handler.
func NewHandler(_ SyslogWriter) slog.Handler {
	return NoopHandler{}
}

// SyslogWriter abstracts the level-specific write methods of *syslog.Writer.
// Exported for mock generation via go.uber.org/mock.
type SyslogWriter interface {
	Debug(m string) error
	Info(m string) error
	Warning(m string) error
	Err(m string) error
}

// Sanitize replaces newlines and NULs that would break syslog single-line framing.
func Sanitize(s string) string {
	return s
}
