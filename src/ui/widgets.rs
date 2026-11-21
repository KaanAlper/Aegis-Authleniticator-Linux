use std::f32::consts::TAU;

use egui::{Color32, Pos2, Rect, RichText, Sense, Stroke, TextureHandle, Ui, Vec2};

pub const AEGIS_BLUE: Color32 = Color32::from_rgb(32, 149, 242);
pub const AEGIS_AMBER: Color32 = Color32::from_rgb(245, 158, 11);
pub const AEGIS_RED: Color32 = Color32::from_rgb(239, 68, 68);

/// Design tokens (Apple-ish: soft surfaces, hairline borders, generous radii).
pub struct Tokens {
    pub bg: Color32,
    pub bar: Color32,
    pub card: Color32,
    pub card_hover: Color32,
    pub border: Color32,
    pub field: Color32,
    pub text: Color32,
    pub muted: Color32,
    pub chip: Color32,
    pub chip_hover: Color32,
}

pub fn tokens(dark: bool) -> Tokens {
    if dark {
        Tokens {
            bg: Color32::from_rgb(14, 15, 19),
            bar: Color32::from_rgb(20, 21, 26),
            card: Color32::from_rgb(25, 27, 33),
            card_hover: Color32::from_rgb(31, 34, 41),
            border: Color32::from_white_alpha(18),
            field: Color32::from_rgb(34, 36, 43),
            text: Color32::from_rgb(244, 245, 247),
            muted: Color32::from_rgb(138, 144, 156),
            chip: Color32::from_white_alpha(14),
            chip_hover: Color32::from_white_alpha(26),
        }
    } else {
        Tokens {
            bg: Color32::from_rgb(242, 242, 247),
            bar: Color32::from_rgb(250, 250, 252),
            card: Color32::WHITE,
            card_hover: Color32::from_rgb(247, 248, 251),
            border: Color32::from_black_alpha(18),
            field: Color32::from_rgb(238, 239, 244),
            text: Color32::from_rgb(28, 28, 30),
            muted: Color32::from_rgb(120, 124, 135),
            chip: Color32::from_black_alpha(12),
            chip_hover: Color32::from_black_alpha(22),
        }
    }
}

fn pill(ui: &mut Ui, label: &str, fill: Color32, hover: Color32, fg: Color32, h: f32, strong: bool) -> egui::Response {
    let font = egui::FontId::proportional(13.0);
    let galley = ui.painter().layout_no_wrap(label.to_string(), font, fg);
    let w = galley.size().x + 26.0;
    let (rect, resp) = ui.allocate_exact_size(Vec2::new(w, h), Sense::click());
    if ui.is_rect_visible(rect) {
        let bg = if resp.is_pointer_button_down_on() {
            hover.gamma_multiply(0.85)
        } else if resp.hovered() {
            hover
        } else {
            fill
        };
        ui.painter().rect_filled(rect, 9.0, bg);
        let font = if strong {
            egui::FontId::proportional(13.0)
        } else {
            egui::FontId::proportional(13.0)
        };
        ui.painter().text(rect.center(), egui::Align2::CENTER_CENTER, label, font, fg);
    }
    resp.on_hover_cursor(egui::CursorIcon::PointingHand)
}

pub fn primary_button(ui: &mut Ui, label: &str) -> egui::Response {
    let label = label.trim_start_matches("+ ");
    pill(ui, label, AEGIS_BLUE, Color32::from_rgb(52, 165, 255), Color32::WHITE, 32.0, true)
}

pub fn secondary_button(ui: &mut Ui, label: &str) -> egui::Response {
    let t = tokens(ui.visuals().dark_mode);
    pill(ui, label, t.chip, t.chip_hover, t.text, 32.0, false)
}

pub fn danger_button(ui: &mut Ui, label: &str) -> egui::Response {
    pill(ui, label, AEGIS_RED, Color32::from_rgb(248, 100, 100), Color32::WHITE, 32.0, true)
}

/// Flat tab-style selector (no capsule): transparent when idle, tinted when selected.
pub fn filter_pill(ui: &mut Ui, selected: bool, label: &str) -> egui::Response {
    let t = tokens(ui.visuals().dark_mode);
    if selected {
        pill(
            ui,
            label,
            Color32::from_rgba_unmultiplied(32, 149, 242, 40),
            Color32::from_rgba_unmultiplied(32, 149, 242, 60),
            AEGIS_BLUE,
            28.0,
            true,
        )
    } else {
        pill(ui, label, Color32::TRANSPARENT, t.chip, t.muted, 28.0, false)
    }
}

/// iOS-style segmented control. Returns the index clicked this frame, if any.
pub fn segmented(ui: &mut Ui, selected: usize, labels: &[&str]) -> Option<usize> {
    let t = tokens(ui.visuals().dark_mode);
    let font = egui::FontId::proportional(13.0);
    let widths: Vec<f32> = labels
        .iter()
        .map(|l| ui.painter().layout_no_wrap(l.to_string(), font.clone(), t.text).size().x + 28.0)
        .collect();
    let total: f32 = widths.iter().sum::<f32>() + 6.0;
    let (rect, _) = ui.allocate_exact_size(Vec2::new(total, 34.0), Sense::hover());
    ui.painter().rect_filled(rect, 10.0, t.chip);
    let mut x = rect.min.x + 3.0;
    let mut clicked = None;
    for (i, (label, w)) in labels.iter().zip(&widths).enumerate() {
        let r = Rect::from_min_size(Pos2::new(x, rect.min.y + 3.0), Vec2::new(*w, 28.0));
        let resp = ui
            .interact(r, egui::Id::new(("seg", rect.min.x as i32, rect.min.y as i32, i)), Sense::click())
            .on_hover_cursor(egui::CursorIcon::PointingHand);
        if i == selected {
            ui.painter().rect_filled(r, 8.0, AEGIS_BLUE);
        } else if resp.hovered() {
            ui.painter().rect_filled(r, 8.0, t.chip_hover);
        }
        let fg = if i == selected { Color32::WHITE } else { t.text };
        ui.painter().text(r.center(), egui::Align2::CENTER_CENTER, *label, font.clone(), fg);
        if resp.clicked() {
            clicked = Some(i);
        }
        x += *w;
    }
    clicked
}

#[derive(Clone, Copy)]
pub enum Icon {
    Star { filled: bool },
    Pencil,
    Copy,
    Translate,
    Trash,
    Lock,
    Gear,
    More,
    Close,
}

/// Small round icon button painted with vector shapes (no font glyph dependence).
pub fn icon_button(ui: &mut Ui, icon: Icon, size: f32, tint: Option<Color32>) -> egui::Response {
    let t = tokens(ui.visuals().dark_mode);
    let (rect, resp) = ui.allocate_exact_size(Vec2::splat(size), Sense::click());
    if ui.is_rect_visible(rect) {
        if resp.hovered() {
            ui.painter().circle_filled(rect.center(), size / 2.0, t.chip_hover);
        }
        let color = tint.unwrap_or(if resp.hovered() { t.text } else { t.muted });
        paint_icon(ui.painter(), icon, rect.center(), size * 0.34, color);
    }
    resp.on_hover_cursor(egui::CursorIcon::PointingHand)
}

pub fn paint_icon(p: &egui::Painter, icon: Icon, c: Pos2, r: f32, color: Color32) {
    let st = Stroke::new(1.6_f32, color);
    match icon {
        Icon::Star { filled } => {
            let mut pts = Vec::with_capacity(10);
            for i in 0..10 {
                let a = -TAU / 4.0 + TAU * (i as f32) / 10.0;
                let rr = if i % 2 == 0 { r } else { r * 0.45 };
                pts.push(Pos2::new(c.x + rr * a.cos(), c.y + rr * a.sin() + r * 0.06));
            }
            if filled {
                p.add(egui::Shape::convex_polygon(pts, color, Stroke::new(1.0_f32, color)));
            } else {
                p.add(egui::Shape::closed_line(pts, st));
            }
        }
        Icon::Pencil => {
            let a = Pos2::new(c.x - r * 0.7, c.y + r * 0.7);
            let b = Pos2::new(c.x + r * 0.55, c.y - r * 0.55);
            p.line_segment([a, b], Stroke::new(3.0_f32, color));
            p.line_segment([a, Pos2::new(a.x - 0.5, a.y + 0.5)], Stroke::new(3.0_f32, color));
            p.line_segment(
                [Pos2::new(c.x - r * 0.9, c.y + r * 0.95), Pos2::new(c.x + r * 0.1, c.y + r * 0.95)],
                Stroke::new(1.2_f32, color),
            );
        }
        Icon::Translate => {
            let u = r * 0.95;
            let back = Rect::from_min_max(
                Pos2::new(c.x - u * 0.05, c.y - u * 0.45),
                Pos2::new(c.x + u, c.y + u),
            );
            p.rect_filled(back, 3.0, color.gamma_multiply(0.45));
            let front = Rect::from_min_max(
                Pos2::new(c.x - u, c.y - u),
                Pos2::new(c.x + u * 0.25, c.y + u * 0.45),
            );
            p.rect_filled(front, 3.0, color);
            p.text(
                front.center(),
                egui::Align2::CENTER_CENTER,
                "A",
                egui::FontId::proportional(u * 1.15),
                Color32::from_rgb(14, 15, 19),
            );
            let bs = Stroke::new(1.3_f32, color);
            p.line_segment([Pos2::new(c.x + u * 0.25, c.y + u * 0.2), Pos2::new(c.x + u * 0.9, c.y + u * 0.2)], bs);
            p.line_segment([Pos2::new(c.x + u * 0.55, c.y), Pos2::new(c.x + u * 0.55, c.y + u * 0.2)], bs);
            p.line_segment([Pos2::new(c.x + u * 0.4, c.y + u * 0.9), Pos2::new(c.x + u * 0.9, c.y + u * 0.3)], bs);
        }
        Icon::Copy => {
            let sz = Vec2::splat(r * 1.15);
            let back = Rect::from_min_size(Pos2::new(c.x - r * 0.85, c.y - r * 0.85), sz);
            let front = Rect::from_min_size(Pos2::new(c.x - r * 0.3, c.y - r * 0.3), sz);
            p.rect_stroke(back, 2.0, st, egui::StrokeKind::Middle);
            p.rect_stroke(front, 2.0, st, egui::StrokeKind::Middle);
        }
        Icon::Trash => {
            let w = r * 0.8;
            let top = c.y - r * 0.55;
            p.line_segment([Pos2::new(c.x - r * 0.95, top), Pos2::new(c.x + r * 0.95, top)], st);
            p.line_segment([Pos2::new(c.x - r * 0.3, top - r * 0.3), Pos2::new(c.x + r * 0.3, top - r * 0.3)], st);
            let body = Rect::from_min_max(Pos2::new(c.x - w, top), Pos2::new(c.x + w, c.y + r * 0.95));
            p.rect_stroke(body, 2.0, st, egui::StrokeKind::Middle);
        }
        Icon::Lock => {
            let body = Rect::from_center_size(Pos2::new(c.x, c.y + r * 0.3), Vec2::new(r * 1.5, r * 1.1));
            p.rect_filled(body, 2.5, color);
            p.circle_stroke(Pos2::new(c.x, c.y - r * 0.2), r * 0.45, st);
        }
        Icon::Gear => {
            p.circle_stroke(c, r * 0.4, st);
            for i in 0..8 {
                let a = TAU * i as f32 / 8.0;
                let (s, co) = a.sin_cos();
                p.line_segment(
                    [Pos2::new(c.x + co * r * 0.7, c.y + s * r * 0.7), Pos2::new(c.x + co * r * 0.98, c.y + s * r * 0.98)],
                    Stroke::new(2.4_f32, color),
                );
            }
            p.circle_stroke(c, r * 0.72, Stroke::new(1.4_f32, color));
        }
        Icon::More => {
            for dx in [-0.7_f32, 0.0, 0.7] {
                p.circle_filled(Pos2::new(c.x + dx * r, c.y), 1.7, color);
            }
        }
        Icon::Close => {
            p.line_segment([Pos2::new(c.x - r * 0.6, c.y - r * 0.6), Pos2::new(c.x + r * 0.6, c.y + r * 0.6)], st);
            p.line_segment([Pos2::new(c.x - r * 0.6, c.y + r * 0.6), Pos2::new(c.x + r * 0.6, c.y - r * 0.6)], st);
        }
    }
}

/// Centered modal with dimmed backdrop. Content is clamped to the window and scrolls
/// when the window is too small. Returns false once the user dismisses it (X / backdrop / Esc).
pub fn modal(
    ctx: &egui::Context,
    id: &str,
    title: &str,
    width: f32,
    add_contents: impl FnOnce(&mut Ui),
) -> bool {
    let dark = ctx.style().visuals.dark_mode;
    let t = tokens(dark);
    let screen = ctx.screen_rect();
    let mut open = true;

    // Backdrop
    let backdrop = egui::Area::new(egui::Id::new((id, "scrim")))
        .order(egui::Order::Middle)
        .fixed_pos(screen.min)
        .show(ctx, |ui| {
            let (rect, resp) = ui.allocate_exact_size(screen.size(), Sense::click());
            ui.painter().rect_filled(rect, 0.0, Color32::from_black_alpha(if dark { 150 } else { 90 }));
            resp
        });
    let backdrop_clicked = backdrop.inner.clicked();

    let w = width.min(screen.width() - 24.0).max(240.0);
    let max_h = (screen.height() - 40.0).max(160.0);

    egui::Area::new(egui::Id::new((id, "panel")))
        .order(egui::Order::Foreground)
        .anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO)
        .show(ctx, |ui| {
            egui::Frame::NONE
                .fill(t.card)
                .stroke(Stroke::new(1.0_f32, t.border))
                .corner_radius(18.0)
                .shadow(egui::Shadow {
                    offset: [0, 12],
                    blur: 40,
                    spread: 0,
                    color: Color32::from_black_alpha(if dark { 160 } else { 60 }),
                })
                .inner_margin(egui::Margin::same(20))
                .show(ui, |ui| {
                    ui.set_width(w - 40.0);
                    ui.set_max_height(max_h - 40.0);
                    ui.spacing_mut().item_spacing = Vec2::new(8.0, 10.0);
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(title).size(17.0).strong().color(t.text));
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if icon_button(ui, Icon::Close, 26.0, None).clicked() {
                                open = false;
                            }
                        });
                    });
                    ui.add_space(2.0);
                    egui::ScrollArea::vertical()
                        .auto_shrink([false, true])
                        .max_height(max_h - 110.0)
                        .show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            add_contents(ui);
                        });
                });
        });

    if backdrop_clicked || ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
        open = false;
    }
    open
}

/// Labeled form row that stacks label above the field (never overflows in narrow windows).
pub fn field_label(ui: &mut Ui, text: &str) {
    let t = tokens(ui.visuals().dark_mode);
    ui.add_space(2.0);
    ui.label(RichText::new(text).size(12.0).color(t.muted));
}

pub fn draw_countdown_ring(ui: &mut Ui, remaining_secs: f32, period: f32, size: f32) {
    let (rect, _resp) = ui.allocate_exact_size(Vec2::splat(size), Sense::hover());
    if !ui.is_rect_visible(rect) {
        return;
    }

    let fraction = (remaining_secs / period.max(1.0)).clamp(0.0, 1.0);
    let color = if remaining_secs <= 5.0 {
        AEGIS_RED
    } else if remaining_secs <= 10.0 {
        AEGIS_AMBER
    } else {
        AEGIS_BLUE
    };

    let painter = ui.painter();
    let center = rect.center();
    let radius = size * 0.42;
    let stroke_width = 3.0_f32;

    let track_color = if ui.visuals().dark_mode {
        Color32::from_white_alpha(26)
    } else {
        Color32::from_black_alpha(26)
    };
    painter.circle_stroke(center, radius, Stroke::new(stroke_width, track_color));

    let segments = 48;
    let active_segments = ((segments as f32) * fraction).ceil() as usize;
    if active_segments >= 1 {
        let start_angle = -TAU / 4.0;
        let total_angle = TAU * fraction;
        let mut points = Vec::with_capacity(active_segments + 1);
        for i in 0..=active_segments {
            let t = i as f32 / active_segments as f32;
            let angle = start_angle + total_angle * t;
            points.push(Pos2::new(
                center.x + radius * angle.cos(),
                center.y + radius * angle.sin(),
            ));
        }
        painter.add(egui::Shape::line(points, Stroke::new(stroke_width, color)));
    }

    let secs_text = format!("{}", remaining_secs.ceil() as u64);
    painter.text(
        center,
        egui::Align2::CENTER_CENTER,
        secs_text,
        egui::FontId::proportional(size * 0.34),
        color,
    );
}

pub fn draw_issuer_avatar(
    ui: &mut Ui,
    issuer: &str,
    name: &str,
    texture: Option<&TextureHandle>,
    size: f32,
) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(size), Sense::hover());
    if !ui.is_rect_visible(rect) {
        return;
    }

    if let Some(tex) = texture {
        let uv = Rect::from_min_max(Pos2::ZERO, Pos2::new(1.0, 1.0));
        ui.painter().image(tex.id(), rect, uv, Color32::WHITE);
        return;
    }

    let label_source = if !issuer.trim().is_empty() {
        issuer.trim()
    } else if !name.trim().is_empty() {
        name.trim()
    } else {
        "?"
    };

    let initials: String = label_source
        .split_whitespace()
        .filter_map(|w| w.chars().next())
        .take(2)
        .collect::<String>()
        .to_uppercase();
    let initials = if initials.is_empty() {
        label_source
            .chars()
            .take(2)
            .collect::<String>()
            .to_uppercase()
    } else {
        initials
    };

    let bg = color_for_label(label_source);
    let painter = ui.painter();
    painter.circle_filled(rect.center(), size * 0.48, bg);
    painter.text(
        rect.center(),
        egui::Align2::CENTER_CENTER,
        initials,
        egui::FontId::proportional(size * 0.38),
        Color32::WHITE,
    );
}

fn color_for_label(label: &str) -> Color32 {
    const PALETTE: &[Color32] = &[
        Color32::from_rgb(32, 149, 242),
        Color32::from_rgb(16, 185, 129),
        Color32::from_rgb(139, 92, 246),
        Color32::from_rgb(236, 72, 153),
        Color32::from_rgb(245, 158, 11),
        Color32::from_rgb(20, 184, 166),
        Color32::from_rgb(99, 102, 241),
        Color32::from_rgb(244, 63, 94),
    ];
    let mut hash: u32 = 2166136261;
    for b in label.bytes() {
        hash ^= u32::from(b);
        hash = hash.wrapping_mul(16777619);
    }
    PALETTE[(hash as usize) % PALETTE.len()]
}

pub fn draw_toast(ctx: &egui::Context, message: &str, is_error: bool) {
    let bg = if is_error {
        Color32::from_rgb(185, 28, 28)
    } else {
        Color32::from_rgb(20, 110, 190)
    };
    egui::Area::new(egui::Id::new("toast_overlay"))
        .anchor(egui::Align2::CENTER_BOTTOM, Vec2::new(0.0, -24.0))
        .interactable(false)
        .show(ctx, |ui| {
            egui::Frame::NONE
                .fill(bg)
                .corner_radius(10.0)
                .inner_margin(egui::Margin::symmetric(18, 10))
                .shadow(egui::Shadow {
                    offset: [0, 4],
                    blur: 14,
                    spread: 0,
                    color: Color32::from_black_alpha(110),
                })
                .show(ui, |ui| {
                    ui.label(RichText::new(message).color(Color32::WHITE).strong());
                });
        });
}

/// Single-line text that is truncated with an ellipsis instead of overflowing.
pub fn fit_text(
    ui: &Ui,
    text: &str,
    font: egui::FontId,
    color: Color32,
    max_width: f32,
) -> std::sync::Arc<egui::Galley> {
    let mut job = egui::text::LayoutJob::simple(text.to_string(), font, color, max_width);
    job.wrap.max_rows = 1;
    job.wrap.break_anywhere = true;
    job.wrap.overflow_character = Some('…');
    ui.painter().layout_job(job)
}

pub fn menu_item(ui: &mut Ui, label: &str) -> bool {
    let t = tokens(ui.visuals().dark_mode);
    menu_item_colored(ui, label, t.text)
}

pub fn menu_item_colored(ui: &mut Ui, label: &str, color: Color32) -> bool {
    let w = ui.available_width().max(190.0);
    let (rect, resp) = ui.allocate_exact_size(Vec2::new(w, 30.0), Sense::click());
    if resp.hovered() {
        ui.painter().rect_filled(rect, 8.0, Color32::from_rgba_unmultiplied(32, 149, 242, 40));
    }
    ui.painter().text(
        Pos2::new(rect.min.x + 10.0, rect.center().y),
        egui::Align2::LEFT_CENTER,
        label,
        egui::FontId::proportional(13.5),
        color,
    );
    let clicked = resp.clicked();
    if clicked {
        ui.close_menu();
    }
    clicked
}
