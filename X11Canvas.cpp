#include "X11Canvas.hpp"
#include <iostream>
#include <cstring>
#include <algorithm>

namespace netguard {

X11Canvas::X11Canvas(int width, int height, const std::string &title)
    : m_width(width), m_height(height), m_title(title),
      m_display(nullptr), m_window(0), m_screen(0), m_gc(0),
      m_backBuffer(0), m_xftDraw(nullptr),
      m_fontRegular(nullptr), m_fontBold(nullptr),
      m_fontLarge(nullptr), m_fontSmall(nullptr)
{
}

X11Canvas::~X11Canvas() {
    close();
}

bool X11Canvas::init() {
    m_display = XOpenDisplay(nullptr);
    if (!m_display) {
        std::cerr << "Failed to open X11 display\n";
        return false;
    }

    m_screen = DefaultScreen(m_display);
    Window root = RootWindow(m_display, m_screen);

    XSetWindowAttributes swa;
    swa.event_mask = ExposureMask | KeyPressMask | ButtonPressMask | ButtonReleaseMask |
                     PointerMotionMask | StructureNotifyMask;
    swa.background_pixel = BlackPixel(m_display, m_screen);

    m_window = XCreateWindow(m_display, root, 100, 100, m_width, m_height, 0,
                             DefaultDepth(m_display, m_screen), InputOutput,
                             DefaultVisual(m_display, m_screen),
                             CWEventMask | CWBackPixel, &swa);

    XStoreName(m_display, m_window, m_title.c_str());

    // Window manager delete message
    Atom wmDelete = XInternAtom(m_display, "WM_DELETE_WINDOW", False);
    XSetWMProtocols(m_display, m_window, &wmDelete, 1);

    m_gc = XCreateGC(m_display, m_window, 0, nullptr);
    m_backBuffer = XCreatePixmap(m_display, m_window, m_width, m_height,
                                 DefaultDepth(m_display, m_screen));

    m_xftDraw = XftDrawCreate(m_display, m_backBuffer,
                              DefaultVisual(m_display, m_screen),
                              DefaultColormap(m_display, m_screen));

    // Load fonts
    m_fontRegular = XftFontOpenName(m_display, m_screen, "DejaVu Sans Mono-10:antialias=true");
    if (!m_fontRegular) m_fontRegular = XftFontOpenName(m_display, m_screen, "monospace-10");

    m_fontBold = XftFontOpenName(m_display, m_screen, "DejaVu Sans Mono-10:bold:antialias=true");
    if (!m_fontBold) m_fontBold = XftFontOpenName(m_display, m_screen, "monospace-10:bold");

    m_fontLarge = XftFontOpenName(m_display, m_screen, "DejaVu Sans Mono-14:bold:antialias=true");
    if (!m_fontLarge) m_fontLarge = XftFontOpenName(m_display, m_screen, "monospace-14:bold");

    m_fontSmall = XftFontOpenName(m_display, m_screen, "DejaVu Sans Mono-8:antialias=true");
    if (!m_fontSmall) m_fontSmall = XftFontOpenName(m_display, m_screen, "monospace-8");

    XMapWindow(m_display, m_window);
    XFlush(m_display);

    return true;
}

void X11Canvas::handleResize(int newWidth, int newHeight) {
    if (newWidth <= 0 || newHeight <= 0) return;
    if (newWidth == m_width && newHeight == m_height) return;

    m_width = newWidth;
    m_height = newHeight;

    if (m_display && m_backBuffer) {
        if (m_xftDraw) {
            XftDrawDestroy(m_xftDraw);
            m_xftDraw = nullptr;
        }
        XFreePixmap(m_display, m_backBuffer);
        m_backBuffer = XCreatePixmap(m_display, m_window, m_width, m_height,
                                     DefaultDepth(m_display, m_screen));
        m_xftDraw = XftDrawCreate(m_display, m_backBuffer,
                                  DefaultVisual(m_display, m_screen),
                                  DefaultColormap(m_display, m_screen));
    }
}

void X11Canvas::close() {
    if (m_display) {
        for (auto &pair : m_xftColorCache) {
            XftColorFree(m_display, DefaultVisual(m_display, m_screen),
                         DefaultColormap(m_display, m_screen), &pair.second);
        }
        m_xftColorCache.clear();

        if (m_fontRegular) XftFontClose(m_display, m_fontRegular);
        if (m_fontBold) XftFontClose(m_display, m_fontBold);
        if (m_fontLarge) XftFontClose(m_display, m_fontLarge);
        if (m_fontSmall) XftFontClose(m_display, m_fontSmall);

        if (m_xftDraw) XftDrawDestroy(m_xftDraw);
        if (m_backBuffer) XFreePixmap(m_display, m_backBuffer);
        if (m_gc) XFreeGC(m_display, m_gc);
        if (m_window) XDestroyWindow(m_display, m_window);
        XCloseDisplay(m_display);

        m_display = nullptr;
    }
}

unsigned long X11Canvas::getX11Color(const Color &c) {
    return ((unsigned long)c.r << 16) | ((unsigned long)c.g << 8) | (unsigned long)c.b;
}

XftColor X11Canvas::getXftColor(const Color &c) {
    uint32_t key = ((uint32_t)c.r << 24) | ((uint32_t)c.g << 16) | ((uint32_t)c.b << 8) | (uint32_t)c.a;
    auto it = m_xftColorCache.find(key);
    if (it != m_xftColorCache.end()) {
        return it->second;
    }

    XRenderColor renderColor;
    renderColor.red   = (unsigned short)(c.r * 257);
    renderColor.green = (unsigned short)(c.g * 257);
    renderColor.blue  = (unsigned short)(c.b * 257);
    renderColor.alpha = (unsigned short)(c.a * 257);

    XftColor xftColor;
    XftColorAllocValue(m_display, DefaultVisual(m_display, m_screen),
                       DefaultColormap(m_display, m_screen),
                       &renderColor, &xftColor);
    m_xftColorCache[key] = xftColor;
    return xftColor;
}

void X11Canvas::beginFrame() {
    // Clear or prepare back buffer
}

void X11Canvas::endFrame() {
    if (m_display && m_window && m_backBuffer) {
        XCopyArea(m_display, m_backBuffer, m_window, m_gc, 0, 0, m_width, m_height, 0, 0);
        XFlush(m_display);
    }
}

void X11Canvas::clear(const Color &c) {
    fillRect(0, 0, m_width, m_height, c);
}

void X11Canvas::fillRect(int x, int y, int w, int h, const Color &c) {
    if (!m_display || !m_backBuffer) return;
    XSetForeground(m_display, m_gc, getX11Color(c));
    XFillRectangle(m_display, m_backBuffer, m_gc, x, y, w, h);
}

void X11Canvas::drawRect(int x, int y, int w, int h, const Color &c, int lineWidth) {
    if (!m_display || !m_backBuffer) return;
    XSetForeground(m_display, m_gc, getX11Color(c));
    XSetLineAttributes(m_display, m_gc, lineWidth, LineSolid, CapButt, JoinMiter);
    XDrawRectangle(m_display, m_backBuffer, m_gc, x, y, w, h);
}

void X11Canvas::fillRoundedRect(int x, int y, int w, int h, int radius, const Color &c) {
    // Fill main box and corners
    fillRect(x + radius, y, w - 2 * radius, h, c);
    fillRect(x, y + radius, radius, h - 2 * radius, c);
    fillRect(x + w - radius, y + radius, radius, h - 2 * radius, c);

    if (!m_display || !m_backBuffer) return;
    XSetForeground(m_display, m_gc, getX11Color(c));
    XFillArc(m_display, m_backBuffer, m_gc, x, y, 2 * radius, 2 * radius, 90 * 64, 90 * 64);
    XFillArc(m_display, m_backBuffer, m_gc, x + w - 2 * radius, y, 2 * radius, 2 * radius, 0 * 64, 90 * 64);
    XFillArc(m_display, m_backBuffer, m_gc, x, y + h - 2 * radius, 2 * radius, 2 * radius, 180 * 64, 90 * 64);
    XFillArc(m_display, m_backBuffer, m_gc, x + w - 2 * radius, y + h - 2 * radius, 2 * radius, 2 * radius, 270 * 64, 90 * 64);
}

void X11Canvas::drawRoundedRect(int x, int y, int w, int h, int radius, const Color &c, int lineWidth) {
    if (!m_display || !m_backBuffer) return;
    XSetForeground(m_display, m_gc, getX11Color(c));
    XSetLineAttributes(m_display, m_gc, lineWidth, LineSolid, CapButt, JoinMiter);

    XDrawLine(m_display, m_backBuffer, m_gc, x + radius, y, x + w - radius, y);
    XDrawLine(m_display, m_backBuffer, m_gc, x + radius, y + h, x + w - radius, y + h);
    XDrawLine(m_display, m_backBuffer, m_gc, x, y + radius, x, y + h - radius);
    XDrawLine(m_display, m_backBuffer, m_gc, x + w, y + radius, x + w, y + h - radius);

    XDrawArc(m_display, m_backBuffer, m_gc, x, y, 2 * radius, 2 * radius, 90 * 64, 90 * 64);
    XDrawArc(m_display, m_backBuffer, m_gc, x + w - 2 * radius, y, 2 * radius, 2 * radius, 0 * 64, 90 * 64);
    XDrawArc(m_display, m_backBuffer, m_gc, x, y + h - 2 * radius, 2 * radius, 2 * radius, 180 * 64, 90 * 64);
    XDrawArc(m_display, m_backBuffer, m_gc, x + w - 2 * radius, y + h - 2 * radius, 2 * radius, 2 * radius, 270 * 64, 90 * 64);
}

void X11Canvas::drawLine(int x1, int y1, int x2, int y2, const Color &c, int lineWidth) {
    if (!m_display || !m_backBuffer) return;
    XSetForeground(m_display, m_gc, getX11Color(c));
    XSetLineAttributes(m_display, m_gc, lineWidth, LineSolid, CapButt, JoinMiter);
    XDrawLine(m_display, m_backBuffer, m_gc, x1, y1, x2, y2);
}

void X11Canvas::drawText(int x, int y, const std::string &text, const Color &c, int fontSize, bool bold) {
    if (!m_xftDraw) return;
    XftFont *font = m_fontRegular;
    if (fontSize >= 14) font = m_fontLarge;
    else if (fontSize <= 9) font = m_fontSmall;
    else if (bold) font = m_fontBold;

    XftColor xftColor = getXftColor(c);
    XftDrawStringUtf8(m_xftDraw, &xftColor, font, x, y,
                      (const FcChar8 *)text.c_str(), text.length());
}

int X11Canvas::getTextWidth(const std::string &text, int fontSize, bool bold) {
    if (!m_display) return text.length() * 8;
    XftFont *font = m_fontRegular;
    if (fontSize >= 14) font = m_fontLarge;
    else if (fontSize <= 9) font = m_fontSmall;
    else if (bold) font = m_fontBold;

    if (!font) return text.length() * 8;

    XGlyphInfo extents;
    XftTextExtentsUtf8(m_display, font, (const FcChar8 *)text.c_str(), text.length(), &extents);
    return extents.xOff;
}

void X11Canvas::drawTextCentered(int x, int y, int w, int h, const std::string &text, const Color &c, int fontSize, bool bold) {
    int textW = getTextWidth(text, fontSize, bold);
    int posX = x + (w - textW) / 2;
    int posY = y + (h / 2) + (fontSize / 3) + 2;
    drawText(posX, posY, text, c, fontSize, bold);
}

void X11Canvas::drawCard(int x, int y, int w, int h, const std::string &title, const Color &bg, const Color &border) {
    fillRoundedRect(x, y, w, h, 6, bg);
    drawRoundedRect(x, y, w, h, 6, border, 1);
    if (!title.empty()) {
        drawText(x + 14, y + 22, title, Color(0, 229, 255), 11, true);
        drawLine(x + 10, y + 32, x + w - 10, y + 32, Color(40, 50, 70), 1);
    }
}

void X11Canvas::drawProgressBar(int x, int y, int w, int h, double progress, const Color &fillColor, const Color &bgColor) {
    fillRoundedRect(x, y, w, h, 3, bgColor);
    progress = std::max(0.0, std::min(1.0, progress));
    int fillW = static_cast<int>(w * progress);
    if (fillW > 0) {
        fillRoundedRect(x, y, fillW, h, 3, fillColor);
    }
}

void X11Canvas::drawPillBadge(int x, int y, int w, int h, const std::string &text, const Color &fillColor, const Color &textColor, bool bold) {
    fillRoundedRect(x, y, w, h, h / 2, fillColor);
    drawTextCentered(x, y, w, h, text, textColor, 8, bold);
}

} // namespace netguard
