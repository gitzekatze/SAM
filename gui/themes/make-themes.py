#!/usr/bin/env python3
"""Generate SAM's four KDE color schemes (whitepaper §2.21.7).

Run from this directory: ./make-themes.py
Writes breeze-light.colors, breeze-dark.colors, breeze-high-contrast.colors
and cachyos-neon.colors in KDE color-scheme format, so KColorScheme and
Kirigami pick them up like any Plasma scheme.
"""

THEMES = {
    "breeze-light": dict(
        name="SAM Breeze Light",
        window=(239, 240, 241), window_alt=(227, 229, 231),
        view=(252, 252, 252), view_alt=(239, 240, 241),
        button=(252, 252, 252), button_alt=(163, 212, 250),
        header=(222, 224, 226), header_alt=(239, 240, 241),
        tooltip=(247, 247, 247), complementary=(42, 46, 50),
        fg=(35, 38, 41), inactive=(112, 125, 138), accent=(61, 174, 233),
        sel_bg=(61, 174, 233), sel_fg=(255, 255, 255),
        link=(41, 128, 185), visited=(155, 89, 182),
        negative=(218, 68, 83), neutral=(246, 116, 0), positive=(39, 174, 96),
    ),
    "breeze-dark": dict(
        name="SAM Breeze Dark",
        window=(32, 35, 38), window_alt=(41, 44, 48),
        view=(20, 22, 24), view_alt=(29, 31, 34),
        button=(41, 44, 48), button_alt=(26, 86, 120),
        header=(41, 44, 48), header_alt=(32, 35, 38),
        tooltip=(41, 44, 48), complementary=(20, 22, 24),
        fg=(252, 252, 252), inactive=(161, 169, 177), accent=(61, 174, 233),
        sel_bg=(61, 174, 233), sel_fg=(252, 252, 252),
        link=(29, 153, 243), visited=(155, 89, 182),
        negative=(218, 68, 83), neutral=(246, 116, 0), positive=(39, 174, 96),
    ),
    "breeze-high-contrast": dict(
        name="SAM Breeze High Contrast",
        window=(0, 0, 0), window_alt=(24, 24, 24),
        view=(0, 0, 0), view_alt=(20, 20, 20),
        button=(16, 16, 16), button_alt=(60, 60, 0),
        header=(10, 10, 10), header_alt=(0, 0, 0),
        tooltip=(0, 0, 0), complementary=(0, 0, 0),
        fg=(255, 255, 255), inactive=(225, 225, 225), accent=(255, 230, 0),
        sel_bg=(255, 230, 0), sel_fg=(0, 0, 0),
        link=(90, 200, 255), visited=(230, 150, 255),
        negative=(255, 90, 90), neutral=(255, 180, 0), positive=(0, 255, 140),
    ),
    "cachyos-neon": dict(
        name="SAM CachyOS Neon",
        window=(17, 19, 27), window_alt=(24, 27, 38),
        view=(11, 12, 19), view_alt=(19, 21, 31),
        button=(27, 30, 43), button_alt=(0, 110, 100),
        header=(22, 24, 35), header_alt=(17, 19, 27),
        tooltip=(27, 30, 43), complementary=(11, 12, 19),
        fg=(226, 244, 248), inactive=(136, 158, 172), accent=(0, 222, 196),
        sel_bg=(0, 196, 174), sel_fg=(8, 10, 14),
        link=(64, 200, 255), visited=(190, 130, 255),
        negative=(255, 64, 120), neutral=(255, 196, 48), positive=(64, 255, 170),
    ),
}


def rgb(c):
    return ",".join(str(v) for v in c)


def section(name, bg, bg_alt, t, fg=None):
    fg = fg or t["fg"]
    return f"""[{name}]
BackgroundAlternate={rgb(bg_alt)}
BackgroundNormal={rgb(bg)}
DecorationFocus={rgb(t['accent'])}
DecorationHover={rgb(t['accent'])}
ForegroundActive={rgb(t['accent'])}
ForegroundInactive={rgb(t['inactive'])}
ForegroundLink={rgb(t['link'])}
ForegroundNegative={rgb(t['negative'])}
ForegroundNeutral={rgb(t['neutral'])}
ForegroundNormal={rgb(fg)}
ForegroundPositive={rgb(t['positive'])}
ForegroundVisited={rgb(t['visited'])}
"""


def scheme(tid, t):
    parts = [
        "[ColorEffects:Disabled]\nColor=56,56,56\nColorAmount=0\nColorEffect=0\nContrastAmount=0.65\nContrastEffect=1\nIntensityAmount=0.1\nIntensityEffect=2\n",
        "[ColorEffects:Inactive]\nChangeSelectionColor=true\nColor=112,111,110\nColorAmount=0.025\nColorEffect=2\nContrastAmount=0.1\nContrastEffect=2\nEnable=false\nIntensityAmount=0\nIntensityEffect=0\n",
        section("Colors:Button", t["button"], t["button_alt"], t),
        section("Colors:Complementary", t["complementary"], t["window_alt"], t, fg=(252, 252, 252) if tid == "breeze-light" else t["fg"]),
        section("Colors:Header", t["header"], t["header_alt"], t),
        section("Colors:Header][Inactive", t["header_alt"], t["header"], t),
        section("Colors:Selection", t["sel_bg"], t["sel_bg"], t, fg=t["sel_fg"]),
        section("Colors:Tooltip", t["tooltip"], t["window_alt"], t),
        section("Colors:View", t["view"], t["view_alt"], t),
        section("Colors:Window", t["window"], t["window_alt"], t),
        f"[General]\nColorScheme={t['name'].replace(' ', '')}\nName={t['name']}\nshadeSortColumn=true\n",
        "[KDE]\ncontrast=4\n",
        f"[WM]\nactiveBackground={rgb(t['header'])}\nactiveBlend={rgb(t['fg'])}\nactiveForeground={rgb(t['fg'])}\ninactiveBackground={rgb(t['header_alt'])}\ninactiveBlend={rgb(t['inactive'])}\ninactiveForeground={rgb(t['inactive'])}\n",
    ]
    return "\n".join(parts)


if __name__ == "__main__":
    for tid, t in THEMES.items():
        with open(f"{tid}.colors", "w") as f:
            f.write(scheme(tid, t))
        print(f"wrote {tid}.colors")
