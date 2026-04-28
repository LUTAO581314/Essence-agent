use std::fmt::Write as FmtWrite;

pub(crate) const WIDTH: usize = 78;

pub(crate) fn style(enabled: bool, code: &str) -> &'static str {
    if !enabled {
        ""
    } else {
        match code {
            "ice" => "\x1b[97;1m",
            "moon" => "\x1b[94;1m",
            "cyan" => "\x1b[36;1m",
            "green" => "\x1b[32;1m",
            "yellow" => "\x1b[33;1m",
            "red" => "\x1b[31;1m",
            "dim" => "\x1b[2m",
            _ => "",
        }
    }
}

pub(crate) fn reset(enabled: bool) -> &'static str {
    if enabled {
        "\x1b[0m"
    } else {
        ""
    }
}

pub(crate) fn top(color: bool) -> String {
    format!(
        "{}+{}+{}",
        style(color, "cyan"),
        "=".repeat(WIDTH),
        reset(color)
    )
}

pub(crate) fn mid(color: bool) -> String {
    format!(
        "{}+{}+{}",
        style(color, "cyan"),
        "-".repeat(WIDTH),
        reset(color)
    )
}

pub(crate) fn row(color: bool, text: impl AsRef<str>) -> String {
    let text = text.as_ref();
    format!(
        "{}|{} {} {}|{}",
        style(color, "cyan"),
        reset(color),
        fit(text, WIDTH - 2),
        style(color, "cyan"),
        reset(color)
    )
}

pub(crate) fn brand_header(title: &str, subtitle: &str, color: bool) -> String {
    let mut output = String::new();
    let ice = style(color, "ice");
    let moon = style(color, "moon");
    let dim = style(color, "dim");
    let reset = reset(color);
    let _ = writeln!(output, "{}", top(color));
    let _ = writeln!(
        output,
        "{}",
        row(
            color,
            format!("{ice}{title}{reset} {dim}//{reset} {moon}{subtitle}{reset}")
        )
    );
    let _ = writeln!(output, "{}", row(color, pixel_flow(color)));
    let _ = writeln!(output, "{}", top(color));
    output
}

pub(crate) fn panel(title: &str, subtitle: &str, body: &str, color: bool) -> String {
    let mut output = brand_header(title, subtitle, color);
    for line in body.lines() {
        let _ = writeln!(output, "{}", row(color, line));
    }
    if body.is_empty() {
        let _ = writeln!(output, "{}", row(color, ""));
    }
    let _ = writeln!(output, "{}", top(color));
    output
}

pub(crate) fn table(
    title: &str,
    subtitle: &str,
    headers: &[&str],
    rows: &[Vec<String>],
    color: bool,
) -> String {
    let mut output = brand_header(title, subtitle, color);
    let header = headers.join("  ");
    let _ = writeln!(output, "{}", row(color, header));
    let _ = writeln!(output, "{}", mid(color));
    if rows.is_empty() {
        let _ = writeln!(
            output,
            "{}",
            row(
                color,
                format!("{}empty{}", style(color, "dim"), reset(color))
            )
        );
    } else {
        for cells in rows {
            let _ = writeln!(output, "{}", row(color, cells.join("  ")));
        }
    }
    let _ = writeln!(output, "{}", top(color));
    output
}

pub(crate) fn error_panel(message: &str, color: bool) -> String {
    panel("ESSENCE ERROR", "command failed", message, color)
}

pub(crate) fn pixel_flow(color: bool) -> String {
    let moon = style(color, "moon");
    let ice = style(color, "ice");
    let dim = style(color, "dim");
    let reset = reset(color);
    format!(
        "{moon}[##]{reset} download  {ice}[##]{reset} configure  {moon}[##]{reset} chat  {dim}[##]{reset} board"
    )
}

pub(crate) fn tiny_logo(color: bool) -> String {
    let ice = style(color, "ice");
    let moon = style(color, "moon");
    let reset = reset(color);
    format!(
        "{moon}/\\_/\\\\{reset} {ice}/ 0 0 \\\\{reset} {ice}\\_ ^ _/{reset}   SNOW SIGNAL // ledger awake"
    )
}

pub(crate) fn key_value(color: bool, key: &str, value: &str) -> String {
    let moon = style(color, "moon");
    let reset = reset(color);
    format!("{moon}{key:<14}{reset} {value}")
}

pub(crate) fn status_chip(color: bool, label: &str, tone: &str) -> String {
    let style = style(color, tone);
    let reset = reset(color);
    format!("{style}[{label}]{reset}")
}

pub(crate) fn fit(value: &str, width: usize) -> String {
    let visible = visible_width(value);
    if visible > width {
        return format!("{:<width$}", truncate(&strip_ansi(value), width));
    }
    format!("{value}{}", " ".repeat(width - visible))
}

pub(crate) fn truncate(value: &str, width: usize) -> String {
    if width == 0 {
        return String::new();
    }
    let mut chars = value.chars();
    let mut output = chars.by_ref().take(width).collect::<String>();
    if chars.next().is_some() && width > 1 {
        output.pop();
        output.push('~');
    }
    output
}

fn visible_width(value: &str) -> usize {
    strip_ansi(value).chars().count()
}

fn strip_ansi(value: &str) -> String {
    let mut output = String::new();
    let mut chars = value.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\x1b' {
            for next in chars.by_ref() {
                if next.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            output.push(ch);
        }
    }
    output
}
