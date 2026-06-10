/**
 * LogsScroll Hook
 *
 * Handles auto-scrolling behavior for the logs viewer.
 * When auto-scroll is enabled, automatically scrolls to bottom
 * when new logs arrive.
 */

export const LogsScroll = {
  mounted() {
    this.autoScroll = true;
    this.userScrolled = false;
    this.scrollTimeout = null;

    // Handle scroll events
    this.el.addEventListener('scroll', () => {
      clearTimeout(this.scrollTimeout);

      // Check if user manually scrolled up
      const isAtBottom = this.isScrolledToBottom();

      if (!isAtBottom) {
        this.userScrolled = true;
      } else {
        this.userScrolled = false;
      }

      // Reset user scroll flag after 2 seconds of no scrolling
      this.scrollTimeout = setTimeout(() => {
        if (this.isScrolledToBottom()) {
          this.userScrolled = false;
        }
      }, 2000);
    });

    // Handle updates
    this.handleEvent('logs:updated', () => {
      if (this.autoScroll && !this.userScrolled) {
        this.scrollToBottom();
      }
    });

    // Handle auto-scroll toggle
    this.handleEvent('auto_scroll:toggle', ({ enabled }) => {
      this.autoScroll = enabled;
      if (enabled) {
        this.userScrolled = false;
        this.scrollToBottom();
      }
    });

    // Initial scroll to bottom
    this.scrollToBottom();
  },

  updated() {
    // Auto-scroll on update if enabled and user hasn't manually scrolled
    if (this.autoScroll && !this.userScrolled) {
      this.scrollToBottom();
    }
  },

  isScrolledToBottom() {
    const threshold = 50; // pixels from bottom
    const scrollHeight = this.el.scrollHeight;
    const scrollTop = this.el.scrollTop;
    const clientHeight = this.el.clientHeight;

    return scrollHeight - scrollTop - clientHeight < threshold;
  },

  scrollToBottom() {
    requestAnimationFrame(() => {
      this.el.scrollTop = this.el.scrollHeight;
    });
  },

  destroyed() {
    clearTimeout(this.scrollTimeout);
  }
};

/**
 * LogsExport Hook
 *
 * Handles client-side log export functionality.
 */
export const LogsExport = {
  mounted() {
    this.handleEvent('download', ({ data, filename, mimetype }) => {
      const blob = new Blob([data], { type: mimetype });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    });
  }
};

/**
 * LogsCopy Hook
 *
 * Handles copying log entries to clipboard.
 */
export const LogsCopy = {
  mounted() {
    this.el.addEventListener('click', (e) => {
      if (e.target.dataset.copy) {
        const logId = e.target.dataset.logId;
        const logElement = document.querySelector(`[data-log-id="${logId}"]`);

        if (logElement) {
          const text = logElement.innerText;

          navigator.clipboard.writeText(text).then(() => {
            // Show success feedback
            const originalText = e.target.innerText;
            e.target.innerText = 'Copied!';
            e.target.classList.add('text-green-400');

            setTimeout(() => {
              e.target.innerText = originalText;
              e.target.classList.remove('text-green-400');
            }, 2000);
          }).catch(err => {
            console.error('Failed to copy:', err);
          });
        }
      }
    });
  }
};

/**
 * LogsFilter Hook
 *
 * Handles client-side log filtering for better performance.
 */
export const LogsFilter = {
  mounted() {
    this.filterDebounce = null;

    this.el.addEventListener('input', (e) => {
      clearTimeout(this.filterDebounce);

      this.filterDebounce = setTimeout(() => {
        const value = e.target.value;
        this.pushEvent('filter:update', { value });
      }, 300);
    });
  },

  destroyed() {
    clearTimeout(this.filterDebounce);
  }
};

/**
 * LogsSyntaxHighlight Hook
 *
 * Applies syntax highlighting to log messages containing code/JSON.
 */
export const LogsSyntaxHighlight = {
  mounted() {
    this.highlightLogs();
  },

  updated() {
    this.highlightLogs();
  },

  highlightLogs() {
    // Find all log messages that look like JSON
    const logMessages = this.el.querySelectorAll('.log-message');

    logMessages.forEach(element => {
      const text = element.textContent;

      // Try to detect and highlight JSON
      if (text.trim().startsWith('{') || text.trim().startsWith('[')) {
        try {
          const parsed = JSON.parse(text);
          const formatted = JSON.stringify(parsed, null, 2);
          element.innerHTML = this.syntaxHighlight(formatted);
          element.classList.add('json-highlighted');
        } catch (e) {
          // Not valid JSON, skip
        }
      }
    });
  },

  syntaxHighlight(json) {
    json = json.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

    return json.replace(
      /("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g,
      (match) => {
        let cls = 'text-gray-400';

        if (/^"/.test(match)) {
          if (/:$/.test(match)) {
            cls = 'text-blue-400'; // key
          } else {
            cls = 'text-green-400'; // string value
          }
        } else if (/true|false/.test(match)) {
          cls = 'text-purple-400'; // boolean
        } else if (/null/.test(match)) {
          cls = 'text-red-400'; // null
        } else {
          cls = 'text-yellow-400'; // number
        }

        return `<span class="${cls}">${match}</span>`;
      }
    );
  }
};
