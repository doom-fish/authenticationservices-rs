//! `ASAuthorizationAppleIDButton` helpers.

/// `ASAuthorizationAppleIDButton.ButtonType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppleIdButtonType {
    SignIn,
    Continue,
    SignUp,
    Default,
}

/// `ASAuthorizationAppleIDButton.Style`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppleIdButtonStyle {
    White,
    WhiteOutline,
    Black,
}

/// Lightweight Rust representation of an `ASAuthorizationAppleIDButton`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AppleIdButton {
    button_type: AppleIdButtonType,
    style: AppleIdButtonStyle,
    corner_radius: f64,
}

impl AppleIdButton {
    #[must_use]
    pub const fn new(button_type: AppleIdButtonType, style: AppleIdButtonStyle) -> Self {
        Self {
            button_type,
            style,
            corner_radius: 0.0,
        }
    }

    #[must_use]
    pub const fn button_type(self) -> AppleIdButtonType {
        self.button_type
    }

    #[must_use]
    pub const fn style(self) -> AppleIdButtonStyle {
        self.style
    }

    #[must_use]
    pub const fn corner_radius(self) -> f64 {
        self.corner_radius
    }

    pub fn set_corner_radius(&mut self, corner_radius: f64) {
        self.corner_radius = corner_radius.max(0.0);
    }
}
