use std::f32::consts::TAU;

use egui::{Color32, Pos2, Rect, RichText, Sense, Stroke, TextureHandle, Ui, Vec2};

pub const AEGIS_BLUE: Color32 = Color32::from_rgb(32, 149, 242);
pub const AEGIS_AMBER: Color32 = Color32::from_rgb(245, 158, 11);
pub const AEGIS_RED: Color32 = Color32::from_rgb(239, 68, 68);

pub fn primary_button(ui: &mut Ui, label: &str) -> egui::Response {
    let btn = egui::Button::new(RichText::new(label).color(Color32::WHITE).strong())
        .fill(AEGIS_BLUE)
        .corner_radius(8.0)
        .min_size(Vec2::new(0.0, 32.0));
    ui.add(btn)
}

pub fn secondary_button(ui: &mut Ui, label: &str) -> egui::Response {
    let fill = if ui.visuals().dark_mode {
        Color32::from_rgb(33, 38, 54)
    } else {
        Color32::from_rgb(229, 234, 242)
    };
    let stroke = if ui.visuals().dark_mode {
        Stroke::new(1.0_f32, Color32::from_rgb(52, 60, 82))
    } else {
        Stroke::new(1.0_f32, Color32::from_rgb(203, 213, 225))
    };
    let btn = egui::Button::new(RichText::new(label))
        .fill(fill)
        .stroke(stroke)
        .corner_radius(8.0)
        .min_size(Vec2::new(0.0, 32.0));
    ui.add(btn)
}

pub fn filter_pill(ui: &mut Ui, selected: bool, label: &str) -> egui::Response {
    let (fill, text_color, stroke) = if selected {
        (AEGIS_BLUE, Color32::WHITE, Stroke::NONE)
    } else if ui.visuals().dark_mode {
        (
            Color32::from_rgb(26, 30, 42),
            Color32::from_rgb(180, 190, 210),
            Stroke::new(1.0_f32, Color32::from_rgb(42, 48, 66)),
        )
    } else {
        (
            Color32::from_rgb(236, 240, 246),
            Color32::from_rgb(51, 65, 85),
            Stroke::new(1.0_f32, Color32::from_rgb(209, 217, 228)),
        )
    };
    let btn = egui::Button::new(RichText::new(label).color(text_color).size(12.5))
        .fill(fill)
        .stroke(stroke)
        .corner_radius(14.0)
        .min_size(Vec2::new(0.0, 26.0));
    ui.add(btn)
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
