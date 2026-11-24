use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Wrap};
use unicode_width::UnicodeWidthStr;

use crate::app::hop_editor::HopSection;
use crate::app::{HostFormEdit, HostFormField, OS_ICON_OPTIONS};
use crate::store::{HostGroup, Identity};
use crate::text_input;
use crate::theme::catalog::StyleRole;
use crate::theme::model::ResolvedTheme;

/// Fixed label column inside the field panel so values line up.
/// Fits `Tags (comma-separated):` without ellipsizing the colon away.
const LABEL_COLS: usize = 24;

/// Eight args: form state plus every list it names (groups, identities) plus
/// the resolved inheritance shown as placeholders, plus chrome. Bundling
/// would only move the list somewhere less visible to the two test callers.
#[allow(clippy::too_many_arguments)]
pub fn render_host_form(
    form: &HostFormEdit,
    groups: &[HostGroup],
    identities: &[Identity],
    inherited: &crate::store::ResolvedConnection,
    hops: Option<&HopSection>,
    width: u16,
    save_hint: &str,
    secret_hints: &str,
    copy_hint: &str,
    theme: &ResolvedTheme,
    border: Style,
) -> super::FormBody {
    let title = if form.metadata_only {
        "Edit metadata (ssh_config)"
    } else if form.id.is_some() {
        "Edit host"
    } else {
        "New host"
    };

    let help = theme.style(StyleRole::FormHelp);
    // The `▸`/`>` glyph in front of the current field is the focus indicator.
    // This form marked focus with direct ANSI accents, which the spec allows to
    // be normalised, so there is no legacy cell to be faithful to and the
    // global role fits. The screens whose marker *did* carry a `theme.rs` style
    // — pickers, group form, keybind editor, tunnel reconnect — keep their own
    // family's marker role instead.
    let focus = theme.style(StyleRole::FocusIndicator);
    let box_style = theme.style(StyleRole::FormHelp);

    // One shared panel around every field row (top + N rows + bottom). Values
    // are ellipsized to a single cell row so the form stays non-scrollable on
    // a 24-row terminal; the hop editor still injects its own nested boxes.
    let box_w = (width as usize).max(20);
    let mut lines = Vec::with_capacity(HostFormField::ALL.len() + 6);
    let mut keep = None;
    if form.metadata_only {
        lines.push((
            Line::from(Span::styled(
                "Connection fields are read-only (from ~/.ssh/config). Edit launcher metadata below.",
                help,
            )),
            None,
        ));
    }
    lines.push((
        Line::from(Span::styled(panel_top(box_w, "fields"), box_style)),
        None,
    ));
    for (index, field) in HostFormField::ALL.into_iter().enumerate() {
        let active = form.field == field;
        let editing = active && form.editing;
        let prefix = if editing {
            "▸ "
        } else if active {
            "> "
        } else {
            "  "
        };
        let read_only = form.metadata_only && field.is_connection_field();
        let (label, display) = match field {
            HostFormField::Address => (
                "Address",
                if editing {
                    text_input::with_cursor(&form.address, form.cursor)
                } else {
                    display_text(&form.address)
                },
            ),
            HostFormField::Label => (
                "Label",
                if editing {
                    text_input::with_cursor(&form.label, form.cursor)
                } else {
                    display_text(&form.label)
                },
            ),
            HostFormField::Name => (
                "Name (alias)",
                if editing {
                    text_input::with_cursor(&form.name, form.cursor)
                } else if form.name.trim().is_empty() {
                    // A save falls back to the address for an empty name.
                    match form.address.trim() {
                        "" => "(defaults to address)".to_string(),
                        address => format!("(defaults to {address})"),
                    }
                } else {
                    display_text(&form.name)
                },
            ),
            HostFormField::Port => (
                "Port",
                if editing {
                    text_input::with_cursor(&form.port, form.cursor)
                } else if form.port.trim().is_empty() {
                    // Cleared = inherit: show what a save would actually dial.
                    format!("inherited: {}", inherited.port)
                } else {
                    display_text(&form.port)
                },
            ),
            HostFormField::Group => ("Group", group_summary(&form.group_ids, groups)),
            HostFormField::Identity => {
                // Picker row 0 is "(inherit from group)": name the identity
                // a save would actually use, or (none).
                let label = if form.identity_index == 0 {
                    match inherited.identity.as_ref() {
                        Some(i) => format!("inherit ({})", i.name),
                        None => "inherit (none)".to_string(),
                    }
                } else {
                    identity_label(form.identity_index - 1, identities)
                };
                ("Identity", label)
            }
            HostFormField::Tags => (
                "Tags (comma-separated)",
                if editing {
                    text_input::with_cursor(&form.tags, form.cursor)
                } else {
                    display_text(&form.tags)
                },
            ),
            HostFormField::ProxyJump => (
                "ProxyJump",
                if editing {
                    text_input::with_cursor(&form.proxy_jump, form.cursor)
                } else if form.proxy_jump.trim().is_empty() {
                    inherited
                        .proxy_jump
                        .as_deref()
                        .map(|v| format!("inherited: {v}"))
                        .unwrap_or_default()
                } else {
                    display_text(&form.proxy_jump)
                },
            ),
            HostFormField::ForwardAgent => (
                "Agent forward",
                match form.forward_agent {
                    Some(true) => "enabled (Space to cycle)".to_string(),
                    Some(false) => "disabled (Space to cycle)".to_string(),
                    None => format!(
                        "inherit ({}) (Space to set)",
                        if inherited.forward_agent {
                            "enabled"
                        } else {
                            "disabled"
                        }
                    ),
                },
            ),
            HostFormField::LegacySsh => (
                "Legacy SSH algs",
                if form.legacy_ssh {
                    "on (+ssh-rsa, Space to toggle)".to_string()
                } else {
                    "off (Space to enable for old servers)".to_string()
                },
            ),
            HostFormField::RemoteCommand => (
                "Startup command",
                if editing {
                    text_input::with_cursor(&form.remote_command, form.cursor)
                } else if form.remote_command.trim().is_empty() {
                    // What the field does, said where it is set (#171).
                    // Short enough for one row of the form at 80 columns.
                    "runs at login, then your shell".to_string()
                } else {
                    display_text(&form.remote_command)
                },
            ),
            HostFormField::Transport => (
                "Transport",
                match form.transport {
                    Some(t) => format!("{} (Space to cycle)", t.label()),
                    None => format!("inherit ({}) (Space to set)", inherited.transport.label()),
                },
            ),
            HostFormField::SessionLogging => (
                "Session log",
                format!(
                    "{} (Space or arrows to cycle)",
                    form.session_logging.label()
                ),
            ),
            HostFormField::Ping => (
                "Ping",
                format!("{} (Space or arrows to cycle)", form.ping.label()),
            ),
            HostFormField::OsIcon => ("OS icon", os_icon_label(form.os_icon_index)),
            HostFormField::Password => (
                "Password",
                // Masked while typing too, now that the field arrives prefilled
                // with the stored secret: walking onto it must not expose one.
                // Show/copy binds live on the row itself (not a second hint
                // line) so a 24-row terminal never has to scroll to find them.
                {
                    let body = if editing && form.password_revealed {
                        text_input::with_cursor(&form.password, form.cursor)
                    } else if editing {
                        text_input::with_cursor(
                            &"\u{25CF}".repeat(form.password.chars().count()),
                            form.cursor,
                        )
                    } else {
                        password_display(&form.password, form.has_password, form.password_revealed)
                    };
                    if active && !secret_hints.is_empty() {
                        format!("{body}    {secret_hints}")
                    } else {
                        body
                    }
                },
            ),
            HostFormField::SecretLookup => (
                "Secret lookup",
                if editing {
                    text_input::with_cursor(&form.secret_lookup, form.cursor)
                } else if form.secret_lookup.trim().is_empty() {
                    "URL=ssh://user@host:port".to_string()
                } else {
                    form.secret_lookup.clone()
                },
            ),
            HostFormField::Username => (
                "Username",
                if editing {
                    text_input::with_cursor(&form.username, form.cursor)
                } else if form.username.trim().is_empty() {
                    inherited
                        .username
                        .as_deref()
                        .map(|v| format!("inherited: {v}"))
                        .unwrap_or_default()
                } else {
                    display_text(&form.username)
                },
            ),
        };
        let suffix = if read_only { " (read-only)" } else { "" };
        let label_style = if editing {
            theme.style(StyleRole::FormLabelEditing)
        } else if active {
            theme.style(StyleRole::FormLabelFocused)
        } else {
            theme.style(StyleRole::FormLabel)
        };
        // Inherited placeholders render muted: they show what a save would
        // actually use, not what the host pins.
        let placeholder = !editing
            && match field {
                HostFormField::Port => form.port.trim().is_empty(),
                HostFormField::ProxyJump => form.proxy_jump.trim().is_empty(),
                HostFormField::Username => form.username.trim().is_empty(),
                HostFormField::SecretLookup => form.secret_lookup.trim().is_empty(),
                HostFormField::Name => form.name.trim().is_empty(),
                HostFormField::RemoteCommand => form.remote_command.trim().is_empty(),
                HostFormField::ForwardAgent => form.forward_agent.is_none(),
                HostFormField::Transport => form.transport.is_none(),
                HostFormField::Identity => form.identity_index == 0,
                _ => false,
            };
        let value_style = if placeholder {
            help
        } else if editing {
            theme.style(StyleRole::FormInputEditing)
        } else if active {
            theme.style(StyleRole::FormInputFocused)
        } else {
            theme.style(StyleRole::FormValue)
        };
        let prefix_style = if active { focus } else { label_style };
        // Left rail + prefix + label column + value. No per-row right `│` so
        // the value stays the last span (click-to-cursor) and editing underline
        // does not paint the border; top/bottom caps still close the panel.
        let value_cols = box_w.saturating_sub(2 + 2 + LABEL_COLS).max(4);
        let label_text = crate::tui::text::pad_ellipsize(&format!("{label}{suffix}:"), LABEL_COLS);
        let value_text = crate::tui::text::pad_ellipsize(&display, value_cols);
        lines.push((
            Line::from(vec![
                Span::styled("\u{2502} ", box_style),
                Span::styled(prefix, prefix_style),
                Span::styled(label_text, label_style),
                Span::styled(value_text, value_style),
            ]),
            Some(index),
        ));
        if field == HostFormField::ProxyJump {
            if let Some(h) = hops {
                keep = super::hop_lines::push_hop_lines(&mut lines, h, theme, width);
            }
        }
    }
    lines.push((
        Line::from(Span::styled(panel_bottom(box_w), box_style)),
        None,
    ));

    // Single hint row under the panel (no blank spacer) so the +2 panel caps
    // stay within the non-scrollable 24-row budget.
    let save = format!("{save_hint}: save");
    let mut hint_parts: Vec<&str> =
        vec!["Tab/↓ next", "Enter picker", "Ctrl+U/W kill", save.as_str()];
    if !copy_hint.is_empty() {
        hint_parts.push(copy_hint);
    }
    hint_parts.push("Esc: cancel");
    lines.push((
        Line::from(Span::styled(hint_parts.join("  \u{2502}  "), help)),
        None,
    ));

    super::FormBody::new(
        lines,
        Block::default()
            .borders(Borders::ALL)
            .border_style(border)
            .title(Span::styled(title, theme.style(StyleRole::PopupTitle))),
        // Field rows are sized to one line; wrap only helps the metadata banner.
        Some(Wrap { trim: true }),
    )
    .keep_visible(keep)
}

fn panel_top(width: usize, title: &str) -> String {
    let head = format!("\u{250c}\u{2500} {title} ");
    let fill = width.saturating_sub(head.width() + 1);
    format!("{head}{}\u{2510}", "\u{2500}".repeat(fill))
}

fn panel_bottom(width: usize) -> String {
    let fill = width.saturating_sub(2);
    format!("\u{2514}{}\u{2518}", "\u{2500}".repeat(fill))
}

fn display_text(value: &str) -> String {
    if value.is_empty() {
        "(empty)".to_string()
    } else {
        value.to_string()
    }
}

/// Comma-separated names of the selected groups, in list order.
fn group_summary(selected: &std::collections::BTreeSet<i64>, groups: &[HostGroup]) -> String {
    let names: Vec<&str> = groups
        .iter()
        .filter(|g| selected.contains(&g.id))
        .map(|g| g.name.as_str())
        .collect();
    if names.is_empty() {
        "(none)".to_string()
    } else {
        names.join(", ")
    }
}

fn os_icon_label(index: usize) -> String {
    OS_ICON_OPTIONS
        .get(index)
        .map(|s| (*s).to_string())
        .unwrap_or_else(|| "(none)".to_string())
}

fn password_display(password: &str, has_password: bool, revealed: bool) -> String {
    if password.is_empty() {
        // `(set)` only survives for a secret the store would not hand back, e.g.
        // a locked keyring: otherwise the field is prefilled and this is honest.
        return if has_password {
            "(set)".to_string()
        } else {
            "(empty)".to_string()
        };
    }
    if revealed {
        password.to_string()
    } else {
        "\u{25CF}".repeat(password.chars().count())
    }
}

fn identity_label(index: usize, identities: &[Identity]) -> String {
    identities
        .get(index)
        .map(|i| i.name.clone())
        .unwrap_or_else(|| "(none)".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    fn team_identity() -> Identity {
        Identity {
            id: 7,
            name: "team".into(),
            username: Some("team-user".into()),
            private_key: None,
            certificate: None,
            has_password: false,
        }
    }

    fn inherited_all_set() -> crate::store::ResolvedConnection {
        crate::store::ResolvedConnection {
            identity_id: Some(7),
            identity: Some(team_identity()),
            username: Some("deploy".into()),
            port: 2222,
            proxy_jump: Some("bastion".into()),
            jump_argv: Some("bastion".into()),
            jump_error: None,
            transport: crate::session_transport::SessionTransport::Mosh,
            forward_agent: true,
        }
    }

    fn empty_form() -> HostFormEdit {
        HostFormEdit {
            id: None,
            address: String::new(),
            username: String::new(),
            label: String::new(),
            name: String::new(),
            port: String::new(),
            group_index: 0,
            group_ids: std::collections::BTreeSet::new(),
            identity_index: 0,
            tags: String::new(),
            proxy_jump: String::new(),
            forward_agent: None,
            legacy_ssh: false,
            remote_command: String::new(),
            transport: None,
            session_logging: crate::session_log::SessionLoggingOverride::Inherit,
            ping: crate::session_log::SessionLoggingOverride::Inherit,
            os_icon_index: 0,
            password: String::new(),
            password_original: String::new(),
            has_password: false,
            secret_lookup: String::new(),
            password_revealed: false,
            field: HostFormField::Address,
            cursor: 0,
            metadata_only: false,
            editing: false,
            edit_snapshot: String::new(),
            dirty: false,
        }
    }

    fn rendered_text(form: &HostFormEdit, inherited: &crate::store::ResolvedConnection) -> String {
        let theme = crate::test_support::resolved_default();
        let backend = TestBackend::new(100, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| {
                let area = frame.area();
                frame.render_widget(
                    render_host_form(
                        form,
                        &[],
                        &[team_identity()],
                        inherited,
                        None,
                        100,
                        "Ctrl+S",
                        "",
                        "",
                        &theme,
                        ratatui::style::Style::default(),
                    ),
                    area,
                );
            })
            .unwrap();
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|c| c.symbol().to_string())
            .collect::<String>()
    }

    #[test]
    fn cleared_fields_show_inherited_placeholders() {
        // Oracle: the literal placeholder strings. An empty form must show
        // what a save would actually dial for every inheritable field —
        // and must NOT show an explicit value anywhere.
        let text = rendered_text(&empty_form(), &inherited_all_set());
        for expected in [
            "inherited: 2222",
            "inherited: deploy",
            "inherited: bastion",
            "inherit (mosh)",
            "inherit (enabled)",
            "inherit (team)",
        ] {
            assert!(
                text.contains(expected),
                "rendered form should contain {expected:?}"
            );
        }
    }

    #[test]
    fn field_panel_draws_a_shared_box() {
        let text = rendered_text(&empty_form(), &inherited_all_set());
        assert!(text.contains("fields"), "panel title missing:\n{text}");
        assert!(
            text.contains('\u{250c}') && text.contains('\u{2514}'),
            "panel corners missing:\n{text}"
        );
        assert!(
            text.contains('\u{2502}'),
            "panel side rail missing:\n{text}"
        );
    }

    #[test]
    fn explicit_values_hide_their_placeholders() {
        // Oracle: the literal explicit strings. A form with every field set
        // must show its own values and no "inherit" text on those rows.
        let mut form = empty_form();
        form.port = "2200".into();
        form.username = "root".into();
        form.proxy_jump = "direct".into();
        form.forward_agent = Some(false);
        form.transport = Some(crate::session_transport::SessionTransport::Ssh);
        form.identity_index = 1;
        let text = rendered_text(&form, &inherited_all_set());
        for expected in [
            "2200",
            "root",
            "direct",
            "disabled (Space to cycle)",
            "ssh (Space to cycle)",
            "team",
        ] {
            assert!(
                text.contains(expected),
                "rendered form should contain {expected:?}"
            );
        }
        for absent in [
            "inherited: 2222",
            "inherited: deploy",
            "inherited: bastion",
            "inherit (mosh)",
            "inherit (enabled)",
            "inherit (team)",
        ] {
            assert!(
                !text.contains(absent),
                "rendered form should not contain {absent:?}"
            );
        }
    }

    /// On a 24-row terminal the form is taller than its popup once the hop
    /// picker is open; the picker (its prompt and key hints) must be scrolled
    /// into view, not clipped while still taking input.
    #[test]
    fn an_open_hop_picker_and_raw_box_are_drawn_at_80x24() {
        use crate::app::tests::{host, test_app};
        use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
        let draw = |app: &crate::app::App| {
            let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
            terminal
                .draw(|frame| crate::tui::render(frame, app))
                .unwrap();
            let buf = terminal.backend().buffer().clone();
            (0..24)
                .map(|y| (0..80).map(|x| buf[(x, y)].symbol()).collect::<String>())
                .collect::<Vec<_>>()
                .join("\n")
        };
        let mut app = test_app(vec![("aa", host("aa")), ("hub", host("hub"))]);
        app.enter_host_form(None, false).unwrap();
        app.host_form.as_mut().unwrap().field = HostFormField::ProxyJump;
        app.handle_key(KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE))
            .unwrap();
        assert!(app.hop_editor.picker.is_some());
        let text = draw(&app);
        assert!(text.contains("Esc close"), "picker footer clipped:\n{text}");
        assert!(text.contains("hub"), "picker rows clipped:\n{text}");

        app.hop_editor.picker = None;
        app.hop_editor.raw = Some(crate::app::hop_editor::RawInput {
            text: "ops@h".into(),
            target: crate::app::hop_editor::PickTarget::Add(0),
        });
        let text = draw(&app);
        assert!(text.contains("raw hop"), "raw box clipped:\n{text}");
        assert!(
            text.contains("Esc cancel"),
            "raw box footer clipped:\n{text}"
        );
    }
}
