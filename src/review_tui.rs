//! Interactive TUI for reviewing agent git changes.
//!
//! `devaipod review <workspace>` opens a ratatui-based interface showing the
//! agent's commits and diffs, with the ability to add inline comments and
//! submit them back to the agent via the review API.

use color_eyre::eyre::{Context, Result};
use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap},
};
use std::io::{self, IsTerminal, Stdout};

// ── Data types mirroring the REST API ────────────────────────────────────────

#[derive(Debug, Clone, serde::Deserialize)]
struct CommitSummary {
    sha: String,
    message: String,
    #[allow(dead_code)]
    author: String,
    #[allow(dead_code)]
    timestamp: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct DiffResponse {
    branch: String,
    commit_count: usize,
    commits: Vec<CommitSummary>,
    diff: String,
    #[allow(dead_code)]
    is_stat: bool,
}

#[derive(Debug, serde::Serialize)]
struct ReviewComment {
    file: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    line: Option<usize>,
    body: String,
}

#[derive(Debug, serde::Serialize)]
struct ReviewRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    comments: Vec<ReviewComment>,
}

#[derive(Debug, serde::Deserialize)]
struct ReviewResponse {
    #[allow(dead_code)]
    success: bool,
    message: String,
}

// ── Parsed diff structures ───────────────────────────────────────────────────

/// A single line from the unified diff, classified by type.
#[derive(Debug, Clone)]
enum DiffLineKind {
    Header,  // @@, diff --, +++, index lines
    Add,     // + lines
    Remove,  // - lines
    Context, // space/unchanged lines
}

#[derive(Debug, Clone)]
struct DiffLine {
    kind: DiffLineKind,
    text: String,
    /// The file this line belongs to (set from the latest `diff --git` header).
    file: Option<String>,
    /// The line number in the new file (for additions and context lines).
    new_line: Option<usize>,
}

/// Parse raw unified diff output into classified lines.
fn parse_diff(raw: &str) -> Vec<DiffLine> {
    let mut lines = Vec::new();
    let mut current_file: Option<String> = None;
    let mut new_line_num: Option<usize> = None;

    for text in raw.lines() {
        if text.starts_with("diff --git ") {
            // Extract file name: "diff --git a/foo b/foo" → "foo"
            if let Some(b_path) = text.split(" b/").last() {
                current_file = Some(b_path.to_string());
            }
            lines.push(DiffLine {
                kind: DiffLineKind::Header,
                text: text.to_string(),
                file: current_file.clone(),
                new_line: None,
            });
            new_line_num = None;
        } else if text.starts_with("@@") {
            // Parse hunk header: @@ -old,count +new,count @@
            if let Some(plus) = text.split('+').nth(1)
                && let Some(start) = plus.split(',').next().or(plus.split(' ').next())
            {
                new_line_num = start.parse().ok();
            }
            lines.push(DiffLine {
                kind: DiffLineKind::Header,
                text: text.to_string(),
                file: current_file.clone(),
                new_line: new_line_num,
            });
        } else if text.starts_with("--- ") || text.starts_with("+++ ") || text.starts_with("index ")
        {
            lines.push(DiffLine {
                kind: DiffLineKind::Header,
                text: text.to_string(),
                file: current_file.clone(),
                new_line: None,
            });
        } else if let Some(rest) = text.strip_prefix('+') {
            let ln = new_line_num;
            if let Some(n) = new_line_num.as_mut() {
                *n += 1;
            }
            lines.push(DiffLine {
                kind: DiffLineKind::Add,
                text: rest.to_string(),
                file: current_file.clone(),
                new_line: ln,
            });
        } else if let Some(rest) = text.strip_prefix('-') {
            lines.push(DiffLine {
                kind: DiffLineKind::Remove,
                text: rest.to_string(),
                file: current_file.clone(),
                new_line: None,
            });
        } else {
            // Context line (starts with space or is blank)
            let content = text.strip_prefix(' ').unwrap_or(text);
            let ln = new_line_num;
            if let Some(n) = new_line_num.as_mut() {
                *n += 1;
            }
            lines.push(DiffLine {
                kind: DiffLineKind::Context,
                text: content.to_string(),
                file: current_file.clone(),
                new_line: ln,
            });
        }
    }
    lines
}

// ── App state ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
enum Focus {
    CommitList,
    DiffView,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AppMode {
    /// Normal browsing mode
    Normal,
    /// Writing a review comment
    Commenting,
    /// Confirmation before submitting review
    SubmitConfirm,
}

/// A pending review comment collected from the user.
#[derive(Debug, Clone)]
struct PendingComment {
    file: String,
    line: Option<usize>,
    body: String,
}

struct ReviewApp {
    pod_name: String,
    api_base: String,
    api_token: String,
    client: reqwest::Client,

    // Data
    diff_data: Option<DiffResponse>,
    diff_lines: Vec<DiffLine>,
    error: Option<String>,
    status_msg: Option<String>,

    // UI state
    mode: AppMode,
    focus: Focus,
    commit_state: ListState,
    diff_scroll: usize,         // vertical scroll offset in diff view
    diff_cursor: usize,         // highlighted line in diff view
    last_visible_height: usize, // tracks actual visible height from last render
    comments: Vec<PendingComment>,
    comment_input: String,   // current comment being typed
    overall_message: String, // overall review message
}

impl ReviewApp {
    fn new(pod_name: String, api_base: String, api_token: String) -> Result<Self> {
        let mut commit_state = ListState::default();
        commit_state.select(Some(0));
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .context("Failed to create HTTP client")?;
        Ok(Self {
            pod_name,
            api_base,
            api_token,
            client,
            diff_data: None,
            diff_lines: Vec::new(),
            error: None,
            status_msg: None,
            mode: AppMode::Normal,
            focus: Focus::CommitList,
            commit_state,
            diff_scroll: 0,
            diff_cursor: 0,
            last_visible_height: 30,
            comments: Vec::new(),
            comment_input: String::new(),
            overall_message: String::new(),
        })
    }

    /// Fetch diff data from the API.
    async fn fetch_diff(&mut self) -> Result<()> {
        let url = format!("{}/api/devaipod/pods/{}/diff", self.api_base, self.pod_name);
        let resp = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.api_token))
            .send()
            .await
            .context("Failed to reach devaipod API")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            self.error = Some(format!("API error {status}: {body}"));
            return Ok(());
        }

        let data: DiffResponse = resp.json().await.context("Failed to parse diff response")?;
        self.diff_lines = parse_diff(&data.diff);
        self.diff_data = Some(data);
        self.error = None;
        Ok(())
    }

    /// Get the diff line at the current cursor position.
    fn current_diff_line(&self) -> Option<&DiffLine> {
        self.diff_lines.get(self.diff_cursor)
    }

    /// Count comments on a specific diff line.
    fn comments_on_line(&self, idx: usize) -> Vec<&PendingComment> {
        if let Some(dl) = self.diff_lines.get(idx)
            && let (Some(file), Some(line)) = (&dl.file, dl.new_line)
        {
            return self
                .comments
                .iter()
                .filter(|c| c.file == *file && c.line == Some(line))
                .collect();
        }
        vec![]
    }

    /// Submit the review to the API.
    async fn submit_review(&mut self) -> Result<()> {
        let url = format!(
            "{}/api/devaipod/pods/{}/review",
            self.api_base, self.pod_name
        );

        let review = ReviewRequest {
            message: if self.overall_message.is_empty() {
                None
            } else {
                Some(self.overall_message.clone())
            },
            comments: self
                .comments
                .iter()
                .map(|c| ReviewComment {
                    file: c.file.clone(),
                    line: c.line,
                    body: c.body.clone(),
                })
                .collect(),
        };

        let resp = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.api_token))
            .json(&review)
            .send()
            .await
            .context("Failed to submit review")?;

        if resp.status().is_success() {
            let result: ReviewResponse = resp.json().await.unwrap_or(ReviewResponse {
                success: true,
                message: "Review submitted".to_string(),
            });
            self.status_msg = Some(result.message);
            self.comments.clear();
            self.overall_message.clear();
        } else {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            self.error = Some(format!("Submit failed ({status}): {body}"));
        }
        Ok(())
    }
}

// ── Drawing ──────────────────────────────────────────────────────────────────

fn draw(f: &mut Frame, app: &mut ReviewApp) {
    let size = f.area();

    // Main layout: header, body, footer
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // header
            Constraint::Min(10),   // body
            Constraint::Length(3), // footer
        ])
        .split(size);

    // Track the actual diff panel height for scroll calculations.
    // Body is split 30/70, diff panel is the 70% side minus 2 for borders.
    let body_height = main_chunks[1].height.saturating_sub(2) as usize;
    app.last_visible_height = body_height.max(5);

    draw_header(f, app, main_chunks[0]);
    draw_body(f, app, main_chunks[1]);
    draw_footer(f, app, main_chunks[2]);

    // Draw overlays
    if app.mode == AppMode::Commenting {
        draw_comment_dialog(f, app, size);
    } else if app.mode == AppMode::SubmitConfirm {
        draw_submit_confirm(f, app, size);
    }
}

fn draw_header(f: &mut Frame, app: &ReviewApp, area: Rect) {
    let branch = app
        .diff_data
        .as_ref()
        .map(|d| d.branch.as_str())
        .unwrap_or("...");
    let commit_count = app.diff_data.as_ref().map(|d| d.commit_count).unwrap_or(0);
    let comment_count = app.comments.len();

    let title = format!(
        " {} │ branch: {} │ {} commit(s) │ {} pending comment(s) ",
        app.pod_name, branch, commit_count, comment_count,
    );

    let header = Paragraph::new(Line::from(vec![Span::styled(
        title,
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    )]))
    .block(Block::default().borders(Borders::ALL));

    f.render_widget(header, area);
}

fn draw_body(f: &mut Frame, app: &mut ReviewApp, area: Rect) {
    if let Some(ref err) = app.error {
        let error_block = Paragraph::new(Line::from(vec![Span::styled(
            err.as_str(),
            Style::default().fg(Color::Red),
        )]))
        .block(
            Block::default()
                .title(" Error ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Red)),
        )
        .wrap(Wrap { trim: false });
        f.render_widget(error_block, area);
        return;
    }

    // Split body: commit list (left 30%) | diff view (right 70%)
    let body_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(30), Constraint::Percentage(70)])
        .split(area);

    draw_commit_list(f, app, body_chunks[0]);
    draw_diff_view(f, app, body_chunks[1]);
}

fn draw_commit_list(f: &mut Frame, app: &mut ReviewApp, area: Rect) {
    let commits = app
        .diff_data
        .as_ref()
        .map(|d| &d.commits)
        .cloned()
        .unwrap_or_default();

    let items: Vec<ListItem> = commits
        .iter()
        .map(|c| {
            let sha_short = &c.sha[..7.min(c.sha.len())];
            let line = Line::from(vec![
                Span::styled(
                    sha_short,
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(" "),
                Span::styled(
                    truncate_str(&c.message, 40),
                    Style::default().fg(Color::White),
                ),
            ]);
            ListItem::new(line)
        })
        .collect();

    let border_style = if app.focus == Focus::CommitList {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let list = List::new(items)
        .block(
            Block::default()
                .title(" Commits ")
                .borders(Borders::ALL)
                .border_style(border_style),
        )
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▸ ");

    f.render_stateful_widget(list, area, &mut app.commit_state);
}

fn draw_diff_view(f: &mut Frame, app: &ReviewApp, area: Rect) {
    let inner_height = area.height.saturating_sub(2) as usize; // minus borders
    let total_lines = app.diff_lines.len();

    // Ensure scroll keeps cursor visible
    let scroll = app.diff_scroll;

    let mut rendered_lines: Vec<Line> = Vec::new();

    for (idx, dl) in app
        .diff_lines
        .iter()
        .enumerate()
        .skip(scroll)
        .take(inner_height)
    {
        let is_cursor = idx == app.diff_cursor;
        let has_comments = !app.comments_on_line(idx).is_empty();

        let line_style = match dl.kind {
            DiffLineKind::Header => Style::default()
                .fg(Color::Blue)
                .add_modifier(Modifier::BOLD),
            DiffLineKind::Add => Style::default().fg(Color::Green),
            DiffLineKind::Remove => Style::default().fg(Color::Red),
            DiffLineKind::Context => Style::default().fg(Color::Gray),
        };

        let prefix = match dl.kind {
            DiffLineKind::Add => "+",
            DiffLineKind::Remove => "-",
            DiffLineKind::Header => "",
            DiffLineKind::Context => " ",
        };

        // Line number gutter
        let gutter = match dl.new_line {
            Some(n) => format!("{:>4} ", n),
            None => "     ".to_string(),
        };

        // Comment marker
        let marker = if has_comments { "💬" } else { "  " };

        let mut spans = vec![
            Span::styled(gutter, Style::default().fg(Color::DarkGray)),
            Span::raw(marker),
            Span::styled(prefix, line_style),
            Span::styled(&dl.text, line_style),
        ];

        if is_cursor && app.focus == Focus::DiffView {
            // Highlight the cursor line
            spans = vec![Span::styled(
                format!(
                    "{}{}{}{}",
                    match dl.new_line {
                        Some(n) => format!("{:>4} ", n),
                        None => "     ".to_string(),
                    },
                    marker,
                    prefix,
                    &dl.text,
                ),
                line_style.bg(Color::Rgb(40, 40, 60)),
            )];
        }

        rendered_lines.push(Line::from(spans));

        // Show inline comments right after the line
        if has_comments {
            for comment in app.comments_on_line(idx) {
                rendered_lines.push(Line::from(vec![
                    Span::raw("     "),
                    Span::styled(
                        format!("  ╰─ {}", comment.body),
                        Style::default()
                            .fg(Color::Magenta)
                            .add_modifier(Modifier::ITALIC),
                    ),
                ]));
            }
        }
    }

    let border_style = if app.focus == Focus::DiffView {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let scroll_info = if total_lines > 0 {
        format!(
            " {}/{} ",
            app.diff_cursor.saturating_add(1).min(total_lines),
            total_lines
        )
    } else {
        String::new()
    };

    let diff_widget = Paragraph::new(rendered_lines).block(
        Block::default()
            .title(" Diff ")
            .title_bottom(Line::from(scroll_info).right_aligned())
            .borders(Borders::ALL)
            .border_style(border_style),
    );

    f.render_widget(diff_widget, area);
}

fn draw_footer(f: &mut Frame, app: &ReviewApp, area: Rect) {
    let hints = match app.mode {
        AppMode::Normal => match app.focus {
            Focus::CommitList => {
                "Tab:switch │ j/k:navigate │ Enter:view diff │ R:submit review │ q:quit"
            }
            Focus::DiffView => "Tab:switch │ j/k:scroll │ c:comment │ R:submit review │ q:quit",
        },
        AppMode::Commenting => "Enter:save comment │ Esc:cancel",
        AppMode::SubmitConfirm => "y:submit │ n:cancel",
    };

    let status = app.status_msg.as_deref().unwrap_or(hints);

    let footer = Paragraph::new(Line::from(vec![Span::styled(
        format!(" {status} "),
        Style::default().fg(Color::White),
    )]))
    .block(Block::default().borders(Borders::ALL));

    f.render_widget(footer, area);
}

fn draw_comment_dialog(f: &mut Frame, app: &ReviewApp, area: Rect) {
    let dialog_width = area.width.min(70);
    let dialog_height: u16 = 8;
    let x = (area.width.saturating_sub(dialog_width)) / 2;
    let y = (area.height.saturating_sub(dialog_height)) / 2;
    let dialog_area = Rect::new(x, y, dialog_width, dialog_height);

    f.render_widget(Clear, dialog_area);

    let context = app
        .current_diff_line()
        .map(|dl| {
            let file = dl.file.as_deref().unwrap_or("unknown");
            match dl.new_line {
                Some(n) => format!("{file}:{n}"),
                None => file.to_string(),
            }
        })
        .unwrap_or_else(|| "unknown".to_string());

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Min(3),
            Constraint::Length(1),
        ])
        .split(dialog_area);

    let label = Paragraph::new(Line::from(vec![
        Span::styled(" Comment on ", Style::default().fg(Color::White)),
        Span::styled(
            &context,
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
    ]))
    .block(
        Block::default()
            .title(" Add Comment ")
            .borders(Borders::TOP | Borders::LEFT | Borders::RIGHT)
            .border_style(Style::default().fg(Color::Magenta)),
    );
    f.render_widget(label, chunks[0]);

    let input = Paragraph::new(Line::from(vec![
        Span::raw(&app.comment_input),
        Span::styled("█", Style::default().fg(Color::White)),
    ]))
    .block(
        Block::default()
            .borders(Borders::LEFT | Borders::RIGHT)
            .border_style(Style::default().fg(Color::Magenta)),
    )
    .wrap(Wrap { trim: false });
    f.render_widget(input, chunks[1]);

    let hint = Paragraph::new(Line::from(Span::styled(
        " Enter: save │ Esc: cancel ",
        Style::default().fg(Color::DarkGray),
    )))
    .block(
        Block::default()
            .borders(Borders::BOTTOM | Borders::LEFT | Borders::RIGHT)
            .border_style(Style::default().fg(Color::Magenta)),
    );
    f.render_widget(hint, chunks[2]);
}

fn draw_submit_confirm(f: &mut Frame, app: &ReviewApp, area: Rect) {
    let dialog_width = area.width.min(60);
    let dialog_height: u16 = 10;
    let x = (area.width.saturating_sub(dialog_width)) / 2;
    let y = (area.height.saturating_sub(dialog_height)) / 2;
    let dialog_area = Rect::new(x, y, dialog_width, dialog_height);

    f.render_widget(Clear, dialog_area);

    let mut lines = vec![
        Line::from(Span::styled(
            format!(" {} comment(s) to submit:", app.comments.len()),
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
    ];

    for (i, c) in app.comments.iter().take(5).enumerate() {
        let loc = match c.line {
            Some(n) => format!("{}:{}", c.file, n),
            None => c.file.clone(),
        };
        lines.push(Line::from(vec![
            Span::styled(
                format!(" {}. ", i + 1),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(loc, Style::default().fg(Color::Yellow)),
            Span::styled(
                format!(" — {}", truncate_str(&c.body, 30)),
                Style::default().fg(Color::White),
            ),
        ]));
    }
    if app.comments.len() > 5 {
        lines.push(Line::from(Span::styled(
            format!(" ... and {} more", app.comments.len() - 5),
            Style::default().fg(Color::DarkGray),
        )));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        " Submit? (y/n) ",
        Style::default()
            .fg(Color::Green)
            .add_modifier(Modifier::BOLD),
    )));

    let confirm = Paragraph::new(lines).block(
        Block::default()
            .title(" Submit Review ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Green)),
    );

    f.render_widget(confirm, dialog_area);
}

fn truncate_str(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        s.to_string()
    } else {
        let truncated: String = s.chars().take(max_chars.saturating_sub(3)).collect();
        format!("{truncated}...")
    }
}

// ── Event handling ───────────────────────────────────────────────────────────

enum Action {
    None,
    Quit,
    Refresh,
    Submit,
}

fn handle_key(app: &mut ReviewApp, key: KeyEvent) -> Action {
    match app.mode {
        AppMode::Normal => handle_normal_key(app, key),
        AppMode::Commenting => handle_comment_key(app, key),
        AppMode::SubmitConfirm => handle_submit_confirm_key(app, key),
    }
}

fn handle_normal_key(app: &mut ReviewApp, key: KeyEvent) -> Action {
    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => Action::Quit,
        KeyCode::Char('r') => Action::Refresh,
        KeyCode::Tab | KeyCode::BackTab => {
            app.focus = match app.focus {
                Focus::CommitList => Focus::DiffView,
                Focus::DiffView => Focus::CommitList,
            };
            Action::None
        }
        KeyCode::Char('R') => {
            if app.comments.is_empty() {
                app.status_msg = Some("No comments to submit. Press 'c' to add comments.".into());
            } else {
                app.mode = AppMode::SubmitConfirm;
            }
            Action::None
        }
        KeyCode::Char('c') if app.focus == Focus::DiffView => {
            app.mode = AppMode::Commenting;
            app.comment_input.clear();
            app.status_msg = None;
            Action::None
        }
        // Navigation
        KeyCode::Char('j') | KeyCode::Down => {
            match app.focus {
                Focus::CommitList => {
                    let count = app.diff_data.as_ref().map(|d| d.commits.len()).unwrap_or(0);
                    if count > 0 {
                        let i = app.commit_state.selected().unwrap_or(0);
                        app.commit_state.select(Some((i + 1).min(count - 1)));
                    }
                }
                Focus::DiffView => {
                    let max = app.diff_lines.len().saturating_sub(1);
                    app.diff_cursor = (app.diff_cursor + 1).min(max);
                    ensure_cursor_visible(app);
                }
            }
            Action::None
        }
        KeyCode::Char('k') | KeyCode::Up => {
            match app.focus {
                Focus::CommitList => {
                    let i = app.commit_state.selected().unwrap_or(0);
                    app.commit_state.select(Some(i.saturating_sub(1)));
                }
                Focus::DiffView => {
                    app.diff_cursor = app.diff_cursor.saturating_sub(1);
                    ensure_cursor_visible(app);
                }
            }
            Action::None
        }
        // Page up/down in diff view
        KeyCode::Char('d') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            if app.focus == Focus::DiffView {
                let page = 20;
                let max = app.diff_lines.len().saturating_sub(1);
                app.diff_cursor = (app.diff_cursor + page).min(max);
                ensure_cursor_visible(app);
            }
            Action::None
        }
        KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            if app.focus == Focus::DiffView {
                app.diff_cursor = app.diff_cursor.saturating_sub(20);
                ensure_cursor_visible(app);
            }
            Action::None
        }
        KeyCode::PageDown => {
            if app.focus == Focus::DiffView {
                let max = app.diff_lines.len().saturating_sub(1);
                app.diff_cursor = (app.diff_cursor + 20).min(max);
                ensure_cursor_visible(app);
            }
            Action::None
        }
        KeyCode::PageUp => {
            if app.focus == Focus::DiffView {
                app.diff_cursor = app.diff_cursor.saturating_sub(20);
                ensure_cursor_visible(app);
            }
            Action::None
        }
        KeyCode::Home | KeyCode::Char('g') => {
            if app.focus == Focus::DiffView {
                app.diff_cursor = 0;
                app.diff_scroll = 0;
            }
            Action::None
        }
        KeyCode::End | KeyCode::Char('G') => {
            if app.focus == Focus::DiffView {
                app.diff_cursor = app.diff_lines.len().saturating_sub(1);
                ensure_cursor_visible(app);
            }
            Action::None
        }
        KeyCode::Enter => {
            if app.focus == Focus::CommitList {
                // Switch to diff view
                app.focus = Focus::DiffView;
                app.diff_cursor = 0;
                app.diff_scroll = 0;
            }
            Action::None
        }
        _ => Action::None,
    }
}

fn handle_comment_key(app: &mut ReviewApp, key: KeyEvent) -> Action {
    match key.code {
        KeyCode::Esc => {
            app.mode = AppMode::Normal;
            app.comment_input.clear();
            Action::None
        }
        KeyCode::Enter => {
            if !app.comment_input.is_empty()
                && let Some(dl) = app.current_diff_line().cloned()
            {
                let file = dl.file.unwrap_or_else(|| "unknown".to_string());
                app.comments.push(PendingComment {
                    file,
                    line: dl.new_line,
                    body: app.comment_input.clone(),
                });
                app.status_msg = Some(format!("Comment added ({} total)", app.comments.len()));
            }
            app.mode = AppMode::Normal;
            app.comment_input.clear();
            Action::None
        }
        KeyCode::Backspace => {
            app.comment_input.pop();
            Action::None
        }
        KeyCode::Char(c) => {
            app.comment_input.push(c);
            Action::None
        }
        _ => Action::None,
    }
}

fn handle_submit_confirm_key(app: &mut ReviewApp, key: KeyEvent) -> Action {
    match key.code {
        KeyCode::Char('y') | KeyCode::Char('Y') => {
            app.mode = AppMode::Normal;
            Action::Submit
        }
        KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
            app.mode = AppMode::Normal;
            Action::None
        }
        _ => Action::None,
    }
}

/// Ensure the diff cursor is within the visible scroll window.
fn ensure_cursor_visible(app: &mut ReviewApp) {
    let visible = app.last_visible_height.max(5);
    if app.diff_cursor < app.diff_scroll {
        app.diff_scroll = app.diff_cursor;
    } else if app.diff_cursor >= app.diff_scroll + visible {
        app.diff_scroll = app.diff_cursor.saturating_sub(visible - 1);
    }
}

// ── Main entry point ─────────────────────────────────────────────────────────

/// Run the review TUI for a given pod.
pub async fn run(pod_name: &str) -> Result<()> {
    if !io::stdout().is_terminal() {
        color_eyre::eyre::bail!(
            "Review TUI requires a terminal. Use the web UI for non-interactive review."
        );
    }

    let api_token = crate::tui::read_api_token()?;
    let port = crate::tui::api_port();
    let api_base = format!("http://127.0.0.1:{port}");

    let mut app = ReviewApp::new(pod_name.to_string(), api_base, api_token)?;

    // Fetch initial data
    app.fetch_diff().await?;

    if app.diff_data.as_ref().is_some_and(|d| d.commit_count == 0) {
        eprintln!(
            "No commits found for pod '{}'. Nothing to review.",
            pod_name
        );
        return Ok(());
    }

    // Setup terminal
    let (mut terminal, kbd_enhanced) = setup_terminal()?;

    let result = run_event_loop(&mut terminal, &mut app).await;

    // Restore terminal
    restore_terminal(&mut terminal, kbd_enhanced)?;

    result
}

fn setup_terminal() -> Result<(Terminal<CrosstermBackend<Stdout>>, bool)> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    let kbd_enhanced = false; // Keep it simple for now
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let terminal = Terminal::new(backend)?;
    Ok((terminal, kbd_enhanced))
}

fn restore_terminal(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    _kbd_enhanced: bool,
) -> Result<()> {
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}

async fn run_event_loop(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    app: &mut ReviewApp,
) -> Result<()> {
    loop {
        terminal.draw(|f| draw(f, app))?;

        // Poll for events with 100ms timeout
        if event::poll(std::time::Duration::from_millis(100))?
            && let Event::Key(key) = event::read()?
            && key.kind == event::KeyEventKind::Press
        {
            match handle_key(app, key) {
                Action::Quit => break,
                Action::Refresh => {
                    app.status_msg = Some("Refreshing...".into());
                    terminal.draw(|f| draw(f, app))?;
                    app.fetch_diff().await?;
                    app.status_msg = Some("Refreshed.".into());
                }
                Action::Submit => {
                    app.status_msg = Some("Submitting review...".into());
                    terminal.draw(|f| draw(f, app))?;
                    app.submit_review().await?;
                }
                Action::None => {}
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_truncate_str_ascii() {
        assert_eq!(truncate_str("hello", 10), "hello");
        assert_eq!(truncate_str("hello world", 8), "hello...");
    }

    #[test]
    fn test_truncate_str_unicode_safe() {
        let emoji = "🎉🎊🎈🎆🎇";
        let result = truncate_str(emoji, 3);
        assert!(result.ends_with("..."));
    }

    #[test]
    fn test_truncate_str_exact() {
        assert_eq!(truncate_str("abc", 3), "abc");
    }

    #[test]
    fn test_parse_diff_empty() {
        assert!(parse_diff("").is_empty());
    }

    #[test]
    fn test_parse_diff_classifications() {
        let input = "diff --git a/f.rs b/f.rs\n--- a/f.rs\n+++ b/f.rs\n@@ -1,3 +1,4 @@\n ctx\n-old\n+new\n+extra";
        let lines = parse_diff(input);
        assert!(lines.iter().all(|l| l.file.as_deref() == Some("f.rs")));
        let adds: Vec<_> = lines
            .iter()
            .filter(|l| matches!(l.kind, DiffLineKind::Add))
            .collect();
        assert_eq!(adds.len(), 2);
        let removes: Vec<_> = lines
            .iter()
            .filter(|l| matches!(l.kind, DiffLineKind::Remove))
            .collect();
        assert_eq!(removes.len(), 1);
    }

    #[test]
    fn test_parse_diff_line_numbers() {
        let input = "@@ -1,2 +10,3 @@\n ctx\n+a\n+b";
        let lines = parse_diff(input);
        let ctx = lines
            .iter()
            .find(|l| matches!(l.kind, DiffLineKind::Context))
            .unwrap();
        assert_eq!(ctx.new_line, Some(10));
        let add = lines
            .iter()
            .find(|l| matches!(l.kind, DiffLineKind::Add))
            .unwrap();
        assert_eq!(add.new_line, Some(11));
    }
}
