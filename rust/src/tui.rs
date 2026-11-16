//! `mask-secrets tui`: install or remove the hook per agent, and watch the block / mask counters.

use crate::install::{self, AgentInfo, HookState};
use crate::stats::{self, Action, Event, Summary};
use ratatui::{
    DefaultTerminal, Frame,
    crossterm::event::{self, Event as Input, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style, Stylize},
    text::{Line, Span},
    widgets::{
        Block, Borders, Cell, List, ListItem, ListState, Paragraph, Row, Sparkline, Table, Tabs,
        Wrap,
    },
};
use std::io::IsTerminal;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const TICK: Duration = Duration::from_millis(1000);
const BLOCKED: Color = Color::Red;
const MASKED: Color = Color::Yellow;
const OK: Color = Color::Green;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Install,
    Stats,
}

struct App {
    tab: Tab,
    agents: Vec<AgentInfo>,
    selected: ListState,
    dry_run: bool,
    messages: Vec<String>,
    log: Option<PathBuf>,
    events: Vec<Event>,
    confirm_clear: bool,
    quit: bool,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn label(name: &str) -> &'static str {
    match name {
        "claude" => "Claude Code",
        "codex" => "Codex",
        _ => "?",
    }
}

impl App {
    fn new() -> App {
        let mut app = App {
            tab: Tab::Install,
            agents: Vec::new(),
            selected: ListState::default().with_selected(Some(0)),
            dry_run: false,
            messages: vec!["Enter installs or removes the hook for the selected agent.".into()],
            log: stats::log_path(),
            events: Vec::new(),
            confirm_clear: false,
            quit: false,
        };
        app.refresh();
        app
    }

    fn refresh(&mut self) {
        self.agents = install::agents();
        self.events = self
            .log
            .as_deref()
            .map(stats::read_events)
            .unwrap_or_default();
    }

    fn say(&mut self, line: impl Into<String>) {
        self.messages.push(line.into());
        let extra = self.messages.len().saturating_sub(50);
        self.messages.drain(..extra);
    }

    fn current(&self) -> Option<&AgentInfo> {
        self.selected.selected().and_then(|i| self.agents.get(i))
    }

    /// Install when the hook is not ours-and-current, remove when it is.
    fn toggle(&mut self, name: &'static str, uninstall: bool) {
        let verb = if uninstall { "Removing" } else { "Installing" };
        self.say(format!(
            "{verb} {}{}",
            label(name),
            if self.dry_run { " (dry run)" } else { "" }
        ));
        match install::apply(name, uninstall, self.dry_run) {
            Ok(lines) => lines.into_iter().for_each(|l| self.say(l)),
            Err(e) => self.say(format!("  error: {e}")),
        }
        if !self.dry_run {
            self.say("Restart running sessions to load the change.");
        }
        self.refresh();
    }

    fn on_key(&mut self, key: KeyEvent) {
        if key.kind != KeyEventKind::Press {
            return;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.quit = true;
            return;
        }
        if self.confirm_clear {
            self.confirm_clear = false;
            if matches!(key.code, KeyCode::Char('y' | 'Y')) {
                match self.log.as_deref().map(stats::clear) {
                    Some(Err(e)) => self.say(format!("cannot clear the log: {e}")),
                    _ => self.say("Counters cleared."),
                }
                self.refresh();
            }
            return;
        }
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => self.quit = true,
            KeyCode::Tab | KeyCode::BackTab => {
                self.tab = if self.tab == Tab::Install {
                    Tab::Stats
                } else {
                    Tab::Install
                };
            }
            KeyCode::Char('1') => self.tab = Tab::Install,
            KeyCode::Char('2') => self.tab = Tab::Stats,
            KeyCode::Char('r') => self.refresh(),
            _ if self.tab == Tab::Install => self.on_install_key(key.code),
            KeyCode::Char('c') if self.log.is_some() => self.confirm_clear = true,
            _ => {}
        }
    }

    fn on_install_key(&mut self, code: KeyCode) {
        let last = self.agents.len().saturating_sub(1);
        let at = self.selected.selected().unwrap_or(0);
        match code {
            KeyCode::Up | KeyCode::Char('k') => self.selected.select(Some(at.saturating_sub(1))),
            KeyCode::Down | KeyCode::Char('j') => self.selected.select(Some((at + 1).min(last))),
            KeyCode::Enter | KeyCode::Char(' ') => {
                if let Some(agent) = self.current() {
                    let (name, installed) = (agent.name, agent.state == HookState::Current);
                    self.toggle(name, installed);
                }
            }
            KeyCode::Char('a') => {
                let names: Vec<&'static str> = self
                    .agents
                    .iter()
                    .filter(|a| a.dir_exists && a.state != HookState::Current)
                    .map(|a| a.name)
                    .collect();
                if names.is_empty() {
                    self.say("Nothing to install: every detected agent already has the hook.");
                }
                names.into_iter().for_each(|n| self.toggle(n, false));
            }
            KeyCode::Char('u') => {
                let names: Vec<&'static str> = self
                    .agents
                    .iter()
                    .filter(|a| a.state != HookState::Missing)
                    .map(|a| a.name)
                    .collect();
                if names.is_empty() {
                    self.say("Nothing to remove.");
                }
                names.into_iter().for_each(|n| self.toggle(n, true));
            }
            KeyCode::Char('d') => {
                self.dry_run = !self.dry_run;
                let state = if self.dry_run {
                    "on: nothing will be written"
                } else {
                    "off"
                };
                self.say(format!("Dry run {state}."));
            }
            _ => {}
        }
    }
}

fn state_span(agent: &AgentInfo) -> Span<'static> {
    match &agent.state {
        HookState::Current => Span::styled("● installed", Style::new().fg(OK)),
        HookState::Other(_) => {
            Span::styled("◐ installed, different command", Style::new().fg(MASKED))
        }
        HookState::Unreadable(_) => Span::styled("✗ config unreadable", Style::new().fg(BLOCKED)),
        HookState::Missing if !agent.dir_exists => {
            Span::styled("○ not found", Style::new().dark_gray())
        }
        HookState::Missing => Span::styled("○ not installed", Style::new().fg(Color::Gray)),
    }
}

fn draw_install(f: &mut Frame, app: &mut App, area: Rect) {
    let [agents_area, detail_area, log_area] = Layout::vertical([
        Constraint::Length(app.agents.len() as u16 + 2),
        Constraint::Length(6),
        Constraint::Min(3),
    ])
    .areas(area);

    let items: Vec<ListItem> = app
        .agents
        .iter()
        .map(|a| {
            let dir = a
                .dir
                .as_ref()
                .map_or(String::from("?"), |d| d.display().to_string());
            ListItem::new(Line::from(vec![
                Span::raw(format!("{:<13}", label(a.name))),
                Span::raw(format!("{dir:<34}")),
                state_span(a),
            ]))
        })
        .collect();
    let list = List::new(items)
        .block(Block::bordered().title(" Agents "))
        .highlight_style(Style::new().add_modifier(Modifier::REVERSED))
        .highlight_symbol("▶ ");
    f.render_stateful_widget(list, agents_area, &mut app.selected);

    let mut detail = Vec::new();
    if let Some(a) = app.current() {
        let hook = install::hook_command_display();
        detail.push(Line::from(format!("Hook command:  {hook}")));
        match &a.state {
            HookState::Other(c) => {
                detail.push(Line::from(format!("Registered:    {c}")).fg(MASKED))
            }
            HookState::Unreadable(why) => detail.push(Line::from(why.clone()).fg(BLOCKED)),
            _ => {}
        }
        if a.feature_on == Some(false) && a.state == HookState::Current {
            detail.push(
                Line::from("Codex ignores hooks until [features] hooks = true; re-run install.")
                    .fg(MASKED),
            );
        }
        if !a.dir_exists {
            detail.push(
                Line::from("Config directory does not exist yet; installing creates it.")
                    .dark_gray(),
            );
        }
        let action = if a.state == HookState::Current {
            "remove the hook"
        } else {
            "install the hook"
        };
        detail.push(Line::from(format!(
            "Enter / space: {action}{}",
            if app.dry_run { "  [dry run]" } else { "" }
        )));
    }
    f.render_widget(
        Paragraph::new(detail)
            .wrap(Wrap { trim: true })
            .block(Block::bordered().title(" Selected ")),
        detail_area,
    );

    let height = log_area.height.saturating_sub(2) as usize;
    let tail = app.messages.len().saturating_sub(height);
    let lines: Vec<Line> = app.messages[tail..]
        .iter()
        .map(|m| Line::from(m.as_str()))
        .collect();
    f.render_widget(
        Paragraph::new(lines).block(Block::bordered().title(" Log ")),
        log_area,
    );
}

fn count_card<'a>(
    title: &'a str,
    s: &Summary,
    pick: impl Fn(&stats::Counts) -> u64,
) -> Paragraph<'a> {
    let row = |name: &str, n: u64| {
        Line::from(vec![
            Span::raw(format!("{name:<9}")),
            Span::styled(n.to_string(), Style::new().bold()),
        ])
    };
    Paragraph::new(vec![
        row("all time", pick(&s.all)),
        row("7 days", pick(&s.last_7d)),
        row("24 hours", pick(&s.last_24h)),
    ])
    .block(Block::bordered().title(title))
}

fn breakdown(
    title: &str,
    map: &std::collections::BTreeMap<String, stats::Counts>,
) -> Table<'static> {
    let mut rows: Vec<_> = map.iter().collect();
    rows.sort_by(|a, b| b.1.total().cmp(&a.1.total()).then(a.0.cmp(b.0)));
    let rows = rows.into_iter().map(|(name, c)| {
        Row::new(vec![
            Cell::from(name.clone()),
            Cell::from(c.blocked.to_string()).style(Style::new().fg(BLOCKED)),
            Cell::from(c.masked.to_string()).style(Style::new().fg(MASKED)),
        ])
    });
    Table::new(
        rows,
        [
            Constraint::Min(8),
            Constraint::Length(8),
            Constraint::Length(8),
        ],
    )
    .header(Row::new(vec!["", "blocked", "masked"]).style(Style::new().dark_gray()))
    .block(Block::bordered().title(format!(" {title} ")))
}

fn draw_stats(f: &mut Frame, app: &App, area: Rect) {
    let now = now();
    let s = stats::summarize(&app.events, now);
    let [cards, charts, tables, recent] = Layout::vertical([
        Constraint::Length(5),
        Constraint::Length(6),
        Constraint::Length(7),
        Constraint::Min(4),
    ])
    .areas(area);

    let [c1, c2, c3] = Layout::horizontal([Constraint::Ratio(1, 3); 3]).areas(cards);
    f.render_widget(count_card(" Blocked ", &s, |c| c.blocked).fg(BLOCKED), c1);
    f.render_widget(count_card(" Masked ", &s, |c| c.masked).fg(MASKED), c2);
    f.render_widget(count_card(" Total ", &s, |c| c.total()), c3);

    let [blocked_area, masked_area] =
        Layout::horizontal([Constraint::Ratio(1, 2); 2]).areas(charts);
    let bars = |pick: fn(&stats::Counts) -> u64| s.hourly.iter().map(pick).collect::<Vec<u64>>();
    let (blocked, masked) = (bars(|c| c.blocked), bars(|c| c.masked));
    f.render_widget(
        Sparkline::default()
            .data(&blocked)
            .style(Style::new().fg(BLOCKED))
            .block(Block::bordered().title(" Blocked per hour, last 24 h ")),
        blocked_area,
    );
    f.render_widget(
        Sparkline::default()
            .data(&masked)
            .style(Style::new().fg(MASKED))
            .block(Block::bordered().title(" Masked per hour, last 24 h ")),
        masked_area,
    );

    let [agent_area, tool_area] = Layout::horizontal([Constraint::Ratio(1, 2); 2]).areas(tables);
    f.render_widget(breakdown("By agent", &s.by_agent), agent_area);
    f.render_widget(breakdown("By tool", &s.by_tool), tool_area);

    let rows = app
        .events
        .iter()
        .rev()
        .take(recent.height.saturating_sub(3) as usize)
        .map(|e| {
            let color = if e.action == Action::Blocked {
                BLOCKED
            } else {
                MASKED
            };
            Row::new(vec![
                Cell::from(format!("{} ago", stats::age(e.ts, now))),
                Cell::from(e.action.as_str()).style(Style::new().fg(color)),
                Cell::from(e.agent.clone()),
                Cell::from(e.tool.clone()),
                Cell::from(e.detail.clone()),
            ])
        });
    let title = match &app.log {
        Some(p) if app.events.is_empty() => format!(" Recent events (none yet) · {} ", p.display()),
        Some(p) => format!(" Recent events · {} ", p.display()),
        None => " Logging is off (MASK_SECRETS_LOG=off) ".into(),
    };
    f.render_widget(
        Table::new(
            rows,
            [
                Constraint::Length(9),
                Constraint::Length(8),
                Constraint::Length(8),
                Constraint::Length(14),
                Constraint::Min(10),
            ],
        )
        .header(
            Row::new(vec!["when", "action", "agent", "tool", "detail"])
                .style(Style::new().dark_gray()),
        )
        .block(Block::bordered().title(title)),
        recent,
    );
}

fn draw(f: &mut Frame, app: &mut App) {
    let [head, body, foot] = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(0),
        Constraint::Length(1),
    ])
    .areas(f.area());
    let titles = ["1 Install", "2 Stats"];
    f.render_widget(
        Tabs::new(titles)
            .select(if app.tab == Tab::Install { 0 } else { 1 })
            .highlight_style(Style::new().bold().fg(Color::Cyan))
            .block(
                Block::new()
                    .borders(Borders::ALL)
                    .title(format!(" mask-secrets {} ", env!("CARGO_PKG_VERSION"))),
            ),
        head,
    );
    match app.tab {
        Tab::Install => draw_install(f, app, body),
        Tab::Stats => draw_stats(f, app, body),
    }
    let keys = if app.confirm_clear {
        " Clear all counters? y = yes, any other key = no".to_string()
    } else if app.tab == Tab::Install {
        " ↑↓ select · enter install/remove · a install all · u remove all · d dry run · tab switch · q quit".to_string()
    } else {
        " tab switch · r refresh · c clear counters · q quit".to_string()
    };
    f.render_widget(Paragraph::new(keys).dark_gray(), foot);
}

fn run_loop(terminal: &mut DefaultTerminal, app: &mut App) -> std::io::Result<()> {
    while !app.quit {
        terminal.draw(|f| draw(f, app))?;
        if event::poll(TICK)? {
            if let Input::Key(key) = event::read()? {
                app.on_key(key);
            }
        } else if app.tab == Tab::Stats {
            app.refresh(); // pick up events logged since the last tick
        }
    }
    Ok(())
}

pub fn run() -> Result<(), String> {
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return Err("the TUI needs an interactive terminal; use `mask-secrets install` or `mask-secrets stats` instead".into());
    }
    let mut app = App::new();
    let mut terminal = ratatui::init();
    let result = run_loop(&mut terminal, &mut app);
    ratatui::restore();
    result.map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{Terminal, backend::TestBackend};

    fn screen(app: &mut App) -> String {
        let mut terminal = Terminal::new(TestBackend::new(100, 34)).unwrap();
        terminal.draw(|f| draw(f, app)).unwrap();
        let buf = terminal.backend().buffer().clone();
        (0..buf.area.height)
            .map(|y| {
                (0..buf.area.width)
                    .map(|x| buf[(x, y)].symbol().to_string())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn both_tabs_render_and_switch() {
        let mut app = App::new();
        app.log = None;
        app.events = vec![Event {
            ts: now(),
            agent: "claude".into(),
            tool: "Read".into(),
            action: Action::Blocked,
            detail: ".env".into(),
        }];
        let install_screen = screen(&mut app);
        assert!(
            install_screen.contains("Claude Code") && install_screen.contains("Codex"),
            "{install_screen}"
        );
        app.on_key(key(KeyCode::Tab));
        let stats_screen = screen(&mut app);
        assert!(
            stats_screen.contains("Blocked") && stats_screen.contains("Logging is off"),
            "{stats_screen}"
        );
        assert!(stats_screen.contains(".env"), "{stats_screen}");
        app.on_key(key(KeyCode::Char('q')));
        assert!(app.quit);
    }
}
