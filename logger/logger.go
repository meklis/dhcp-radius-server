package logger

import (
	"fmt"
	"io"
	"os"
	"path"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Level values match the log_level config option. Note that Info is the most verbose.
type Level int

const (
	CriticalLevel Level = iota + 1
	ErrorLevel
	WarningLevel
	NoticeLevel
	DebugLevel
	InfoLevel
)

var (
	levelNames  = [...]string{"", "CRITICAL", "ERROR", "WARNING", "NOTICE", "DEBUG", "INFO"}
	levelColors = [...]string{"", "\033[35m", "\033[31m", "\033[33m", "\033[32m", "\033[36m", "\033[37m"}
	lineCounter atomic.Uint64
)

const (
	timeFormat = "2006-01-02 15:04:05"
	colorReset = "\033[0m"
)

type Options struct {
	Level     Level
	Color     bool
	PrintFile bool
}

type Logger struct {
	mu   sync.Mutex
	out  io.Writer
	opts Options
}

func New(out io.Writer, opts Options) *Logger {
	return &Logger{out: out, opts: opts}
}

func (l *Logger) CriticalF(format string, a ...any) { l.write(CriticalLevel, format, a) }
func (l *Logger) ErrorF(format string, a ...any)    { l.write(ErrorLevel, format, a) }
func (l *Logger) WarningF(format string, a ...any)  { l.write(WarningLevel, format, a) }
func (l *Logger) NoticeF(format string, a ...any)   { l.write(NoticeLevel, format, a) }
func (l *Logger) DebugF(format string, a ...any)    { l.write(DebugLevel, format, a) }
func (l *Logger) InfoF(format string, a ...any)     { l.write(InfoLevel, format, a) }

func (l *Logger) FatalF(format string, a ...any) {
	l.write(CriticalLevel, format, a)
	os.Exit(1)
}

func (l *Logger) write(level Level, format string, args []any) {
	if level > l.opts.Level {
		return
	}
	var b strings.Builder
	if l.opts.Color {
		b.WriteString(levelColors[level])
	}
	fmt.Fprintf(&b, "#%d %s ", lineCounter.Add(1), time.Now().Format(timeFormat))
	if l.opts.PrintFile {
		_, file, line, _ := runtime.Caller(2)
		fmt.Fprintf(&b, "(%s:%d) ", path.Base(file), line)
	}
	b.WriteString("> ")
	b.WriteString(levelNames[level])
	b.WriteByte(' ')
	fmt.Fprintf(&b, format, args...)
	if l.opts.Color {
		b.WriteString(colorReset)
	}
	b.WriteByte('\n')

	l.mu.Lock()
	defer l.mu.Unlock()
	io.WriteString(l.out, b.String())
}
