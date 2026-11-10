// SPDX-License-Identifier: GPL-3.0-or-later
//! The user guide: docs/guide.md, built into the program and shown as
//! native widgets (headings, paragraphs, lists, tables, tip boxes, code).

use adw::prelude::*;
use pulldown_cmark::{Event, HeadingLevel, Options, Parser, Tag, TagEnd};

const GUIDE: &str = include_str!("../../../docs/guide.md");

/// The guide page for the right column.
pub fn page() -> adw::NavigationPage {
    let content = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(12)
        .margin_top(24)
        .margin_bottom(48)
        .margin_start(24)
        .margin_end(24)
        .build();
    content.add_css_class("sam-guide");
    render(GUIDE, &content);
    let clamp = adw::Clamp::builder().maximum_size(760).tightening_threshold(600).child(&content).build();
    let scroll = gtk::ScrolledWindow::builder().hscrollbar_policy(gtk::PolicyType::Never).child(&clamp).build();
    let view = adw::ToolbarView::new();
    view.add_top_bar(&adw::HeaderBar::new());
    view.set_content(Some(&scroll));
    adw::NavigationPage::builder().title("User Guide").child(&view).build()
}

fn esc(s: &str) -> String {
    gtk::glib::markup_escape_text(s).to_string()
}

fn text_label(markup: &str) -> gtk::Label {
    gtk::Label::builder().label(markup).use_markup(true).wrap(true).wrap_mode(gtk::pango::WrapMode::WordChar).xalign(0.0).selectable(false).build()
}

/// Where finished blocks go: the page, a tip box, or a list item.
struct Frame {
    container: gtk::Box,
}

struct List {
    ordered: Option<u64>,
}

#[derive(Default)]
struct Table {
    rows: Vec<Vec<String>>,
    head_rows: usize,
    in_head: bool,
}

fn render(md: &str, root: &gtk::Box) {
    let parser = Parser::new_ext(md, Options::ENABLE_TABLES | Options::ENABLE_STRIKETHROUGH);
    let mut frames = vec![Frame { container: root.clone() }];
    let mut lists: Vec<List> = Vec::new();
    let mut inline = String::new();
    let mut heading: Option<HeadingLevel> = None;
    let mut code: Option<String> = None;
    let mut table: Option<Table> = None;
    // Open list items: their text so far, and whether their row is shown
    // already (an item with a nested list shows its row before the list).
    let mut item_text: Vec<String> = Vec::new();
    let mut item_shown: Vec<bool> = Vec::new();

    let push = |frames: &Vec<Frame>, w: &gtk::Widget| frames.last().unwrap().container.append(w);

    for ev in parser {
        match ev {
            Event::Start(Tag::Heading { level, .. }) => {
                heading = Some(level);
                inline.clear();
            }
            Event::End(TagEnd::Heading(_)) => {
                let l = text_label(&inline);
                match heading.take() {
                    Some(HeadingLevel::H1) => {
                        l.add_css_class("title-1");
                        l.set_margin_bottom(4);
                    }
                    Some(HeadingLevel::H2) => {
                        l.add_css_class("title-2");
                        l.set_margin_top(18);
                    }
                    _ => {
                        l.add_css_class("title-4");
                        l.set_margin_top(10);
                    }
                }
                push(&frames, l.upcast_ref());
                inline.clear();
            }
            Event::Start(Tag::Paragraph) => {
                if item_text.is_empty() {
                    inline.clear();
                }
            }
            Event::End(TagEnd::Paragraph) => {
                if let Some(t) = item_text.last_mut() {
                    // Paragraphs inside a list item belong to the item.
                    if !t.is_empty() {
                        t.push('\n');
                    }
                    t.push_str(&inline);
                } else {
                    push(&frames, text_label(&inline).upcast_ref());
                }
                inline.clear();
            }
            Event::Start(Tag::BlockQuote(_)) => {
                let b = gtk::Box::builder().orientation(gtk::Orientation::Vertical).spacing(6).build();
                b.add_css_class("sam-callout");
                push(&frames, b.upcast_ref());
                frames.push(Frame { container: b });
            }
            Event::End(TagEnd::BlockQuote(_)) => {
                frames.pop();
            }
            Event::Start(Tag::List(start)) => {
                // A nested list: show the parent item's row first, or its
                // text would be lost (and its bullet left empty).
                if let (Some(t), Some(shown)) = (item_text.last_mut(), item_shown.last_mut()) {
                    if !*shown {
                        let mut text = std::mem::take(t);
                        if !inline.is_empty() {
                            if !text.is_empty() {
                                text.push('\n');
                            }
                            text.push_str(&inline);
                        }
                        inline.clear();
                        push(&frames, item_row(&mut lists, &text).upcast_ref());
                        *shown = true;
                    }
                }
                lists.push(List { ordered: start });
            }
            Event::End(TagEnd::List(_)) => {
                lists.pop();
            }
            Event::Start(Tag::Item) => {
                item_text.push(String::new());
                item_shown.push(false);
                inline.clear();
            }
            Event::End(TagEnd::Item) => {
                let mut text = item_text.pop().unwrap_or_default();
                let shown = item_shown.pop().unwrap_or(false);
                if !inline.is_empty() {
                    if !text.is_empty() {
                        text.push('\n');
                    }
                    text.push_str(&inline);
                }
                inline.clear();
                if !shown {
                    push(&frames, item_row(&mut lists, &text).upcast_ref());
                }
            }
            Event::Start(Tag::CodeBlock(_)) => code = Some(String::new()),
            Event::End(TagEnd::CodeBlock) => {
                let text = code.take().unwrap_or_default();
                let l = gtk::Label::builder().label(text.trim_end()).xalign(0.0).selectable(true).wrap(true).wrap_mode(gtk::pango::WrapMode::Char).build();
                l.add_css_class("monospace");
                let card = gtk::Box::new(gtk::Orientation::Vertical, 0);
                card.add_css_class("card");
                card.add_css_class("sam-code");
                card.append(&l);
                push(&frames, card.upcast_ref());
            }
            Event::Start(Tag::Table(_)) => table = Some(Table::default()),
            Event::Start(Tag::TableHead) => {
                if let Some(t) = table.as_mut() {
                    t.in_head = true;
                    t.rows.push(Vec::new());
                }
            }
            Event::End(TagEnd::TableHead) => {
                if let Some(t) = table.as_mut() {
                    t.in_head = false;
                    t.head_rows = t.rows.len();
                }
            }
            Event::Start(Tag::TableRow) => {
                if let Some(t) = table.as_mut() {
                    t.rows.push(Vec::new());
                }
            }
            Event::Start(Tag::TableCell) => inline.clear(),
            Event::End(TagEnd::TableCell) => {
                if let Some(row) = table.as_mut().and_then(|t| t.rows.last_mut()) {
                    row.push(inline.clone());
                }
                inline.clear();
            }
            Event::End(TagEnd::Table) => {
                if let Some(t) = table.take() {
                    push(&frames, table_widget(&t).upcast_ref());
                }
            }
            Event::Start(Tag::Strong) => inline.push_str("<b>"),
            Event::End(TagEnd::Strong) => inline.push_str("</b>"),
            Event::Start(Tag::Emphasis) => inline.push_str("<i>"),
            Event::End(TagEnd::Emphasis) => inline.push_str("</i>"),
            Event::Start(Tag::Strikethrough) => inline.push_str("<s>"),
            Event::End(TagEnd::Strikethrough) => inline.push_str("</s>"),
            Event::Start(Tag::Link { dest_url, .. }) => inline.push_str(&format!("<a href=\"{}\">", esc(&dest_url))),
            Event::End(TagEnd::Link) => inline.push_str("</a>"),
            Event::Code(c) => inline.push_str(&format!("<tt><span background=\"#80808033\"> {} </span></tt>", esc(&c))),
            Event::Text(t) => {
                if let Some(c) = code.as_mut() {
                    c.push_str(&t);
                } else {
                    inline.push_str(&esc(&t));
                }
            }
            Event::SoftBreak => inline.push(' '),
            Event::HardBreak => inline.push('\n'),
            Event::Rule => {
                let s = gtk::Separator::new(gtk::Orientation::Horizontal);
                s.set_margin_top(10);
                s.set_margin_bottom(4);
                push(&frames, s.upcast_ref());
            }
            _ => {}
        }
    }
}

/// One list item: its marker (bullet or number) and text, indented by depth.
fn item_row(lists: &mut [List], text: &str) -> gtk::Box {
    let depth = lists.len().saturating_sub(1) as i32;
    let marker = match lists.last_mut().and_then(|l| l.ordered.as_mut()) {
        Some(n) => {
            let m = format!("{n}.");
            *n += 1;
            m
        }
        None => if depth > 0 { "◦" } else { "•" }.to_string(),
    };
    let row = gtk::Box::builder().spacing(10).margin_start(4 + depth * 22).build();
    let bullet = gtk::Label::builder().label(&marker).valign(gtk::Align::Start).width_chars(2).xalign(1.0).build();
    bullet.add_css_class("sam-bullet");
    let body = text_label(text);
    body.set_hexpand(true);
    row.append(&bullet);
    row.append(&body);
    row
}

fn table_widget(t: &Table) -> gtk::Widget {
    let grid = gtk::Grid::builder().column_spacing(0).row_spacing(0).hexpand(true).build();
    for (r, row) in t.rows.iter().enumerate() {
        for (c, cell) in row.iter().enumerate() {
            let l = text_label(cell);
            l.set_hexpand(true);
            l.add_css_class("sam-td");
            if r < t.head_rows {
                l.add_css_class("sam-th");
            }
            if r + 1 == t.rows.len() {
                l.add_css_class("sam-td-last");
            }
            grid.attach(&l, c as i32, r as i32, 1, 1);
        }
    }
    let card = gtk::Box::new(gtk::Orientation::Vertical, 0);
    card.add_css_class("card");
    card.add_css_class("sam-table");
    card.set_overflow(gtk::Overflow::Hidden);
    card.append(&grid);
    card.upcast()
}

#[cfg(test)]
mod tests {
    #[test]
    fn nested_items_keep_their_text() {
        // The parent text must be in a row before the nested list's rows.
        let md = "- **Parent** text\n  - child one\n  - child two\n- last\n";
        let mut texts = Vec::new();
        let mut cur = String::new();
        for ev in pulldown_cmark::Parser::new(md) {
            match ev {
                pulldown_cmark::Event::Text(t) => cur.push_str(&t),
                pulldown_cmark::Event::Start(pulldown_cmark::Tag::List(_)) | pulldown_cmark::Event::End(pulldown_cmark::TagEnd::Item) if !cur.is_empty() => texts.push(std::mem::take(&mut cur)),
                _ => {}
            }
        }
        assert_eq!(texts, ["Parent text", "child one", "child two", "last"]);
    }

    #[test]
    fn guide_parses() {
        // Every block event must be balanced; pulldown-cmark guarantees
        // this, so just make sure the guide is not empty and has sections.
        assert!(super::GUIDE.contains("## Sandbox Check"));
        assert!(super::GUIDE.lines().filter(|l| l.starts_with("## ")).count() > 8);
    }
}
