// SPDX-License-Identifier: GPL-3.0-or-later
//! Translations: the window uses the same gettext setup as the rest of
//! SAM (`sam_core::i18n`), so texts from the window and from `sam-jail`
//! come from one catalogue per language.

pub use sam_core::i18n::{tr, trf, trn};

/// Sets up gettext for the user's locale. GTK sets the locale itself when
/// it starts (`setlocale(LC_ALL, "")`); this only tells gettext where SAM's
/// catalogue is.
pub fn init() {
    sam_core::i18n::init(false);
}
