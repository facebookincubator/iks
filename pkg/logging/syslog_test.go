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
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// capturedMsg records a syslog message with its level for assertion.
type capturedMsg struct {
	level string
	text  string
}

// SetupMockCapture configures the mock to capture all messages into the returned slice.
// Exported so downstream packages (e.g. client) can reuse it in their tests.
func SetupMockCapture(mock *MockSyslogWriter) *[]capturedMsg {
	msgs := &[]capturedMsg{}
	mock.EXPECT().Debug(gomock.Any()).DoAndReturn(func(m string) error {
		*msgs = append(*msgs, capturedMsg{"DEBUG", m})
		return nil
	}).AnyTimes()
	mock.EXPECT().Info(gomock.Any()).DoAndReturn(func(m string) error {
		*msgs = append(*msgs, capturedMsg{"INFO", m})
		return nil
	}).AnyTimes()
	mock.EXPECT().Warning(gomock.Any()).DoAndReturn(func(m string) error {
		*msgs = append(*msgs, capturedMsg{"WARNING", m})
		return nil
	}).AnyTimes()
	mock.EXPECT().Err(gomock.Any()).DoAndReturn(func(m string) error {
		*msgs = append(*msgs, capturedMsg{"ERR", m})
		return nil
	}).AnyTimes()
	return msgs
}

func TestHandlerEmitsMessage(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockSyslogWriter(ctrl)
	msgs := SetupMockCapture(mock)

	h := NewHandler(mock)
	log := slog.New(h)

	log.Info("test-message", "component", "iksclient")

	require.Len(t, *msgs, 1)
	assert.Equal(t, "INFO", (*msgs)[0].level)
	assert.Contains(t, (*msgs)[0].text, "test-message")
	assert.Contains(t, (*msgs)[0].text, "component=iksclient")
}

func TestHandlerLevelMapping(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockSyslogWriter(ctrl)
	msgs := SetupMockCapture(mock)

	h := NewHandler(mock)
	log := slog.New(h)

	log.Debug("d")
	log.Info("i")
	log.Warn("w")
	log.Error("e")

	require.Len(t, *msgs, 4)
	assert.Equal(t, "DEBUG", (*msgs)[0].level)
	assert.Equal(t, "INFO", (*msgs)[1].level)
	assert.Equal(t, "WARNING", (*msgs)[2].level)
	assert.Equal(t, "ERR", (*msgs)[3].level)
}

func TestHandlerWithAttrsCarriesForward(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockSyslogWriter(ctrl)
	msgs := SetupMockCapture(mock)

	h := NewHandler(mock)
	log := slog.New(h).With("k", "v")

	log.Info("msg")

	require.Len(t, *msgs, 1)
	assert.Contains(t, (*msgs)[0].text, "k=v")
}

func TestNewlineSanitization(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockSyslogWriter(ctrl)
	msgs := SetupMockCapture(mock)

	h := NewHandler(mock)
	log := slog.New(h)

	log.Info("line one\nline two\rline three", "key", "val\nwith\nnewlines")

	require.Len(t, *msgs, 1)
	body := (*msgs)[0].text

	assert.NotContains(t, body, "\n")
	assert.NotContains(t, body, "\r")
	assert.Contains(t, body, "line one line two line three")
	assert.Contains(t, body, "val with newlines")
}

func TestNoopWhenDisabled(t *testing.T) {
	h := NoopHandler{}

	assert.False(t, h.Enabled(context.Background(), slog.LevelError))
	assert.NoError(t, h.Handle(context.Background(), slog.Record{}))
	assert.IsType(t, NoopHandler{}, h.WithAttrs(nil))
	assert.IsType(t, NoopHandler{}, h.WithGroup("x"))
}

func TestLogIncludesBinaryName(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockSyslogWriter(ctrl)
	msgs := SetupMockCapture(mock)

	exe, _ := os.Executable()
	binaryName := filepath.Base(exe)
	logger := slog.New(NewHandler(mock)).With("binary", binaryName)

	logger.Info("test")

	require.NotEmpty(t, *msgs)
	assert.Contains(t, (*msgs)[0].text, "binary=")
	assert.NotContains(t, (*msgs)[0].text, "binary=unknown")
}

func TestWithGroupEmptyNameReturnsReceiver(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockSyslogWriter(ctrl)
	msgs := SetupMockCapture(mock)

	h := NewHandler(mock)
	log := slog.New(h).WithGroup("grp").WithGroup("").With("key", "val")

	log.Info("msg")

	require.Len(t, *msgs, 1)
	body := (*msgs)[0].text
	assert.Contains(t, body, "grp.key=val")
	assert.NotContains(t, body, "grp..key")
}

func TestWithGroupOnlyPrefixesSubsequentAttrs(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockSyslogWriter(ctrl)
	msgs := SetupMockCapture(mock)

	h := NewHandler(mock)
	log := slog.New(h).With("before", "v1").WithGroup("grp").With("after", "v2")

	log.Info("msg", "inline", "v3")

	require.Len(t, *msgs, 1)
	body := (*msgs)[0].text
	// "before" was added before WithGroup — should NOT have group prefix
	assert.Contains(t, body, "before=v1")
	assert.NotContains(t, body, "grp.before")
	// "after" was added after WithGroup — should have group prefix
	assert.Contains(t, body, "grp.after=v2")
	// inline attr in the log call — should also have group prefix
	assert.Contains(t, body, "grp.inline=v3")
}
