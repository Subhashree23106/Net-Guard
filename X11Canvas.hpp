#ifndef NETGUARD_X11_CANVAS_HPP
#define NETGUARD_X11_CANVAS_HPP

#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/Xft/Xft.h>
#include <string>
#include <vector>
#include <functional>
#include <cstdint>
#include <unordered_map>

namespace netguard {

struct Color {
    uint8_t r, g, b, a;
    Color(uint8_t _r = 0, uint8_t _g = 0, uint8_t _b = 0, uint8_t _a = 255)
        : r(_r), g(_g), b(_b), a(_a) {}

    static Color fromHex(uint32_t hex) {
        return Color((hex >> 16) & 0xFF, (hex >> 8) & 0xFF, hex & 0xFF);
    }
};

class X11Canvas {
public:
    X11Canvas(int width = 1200, int height = 800, const std::string &title = "NetGuard - Kernel Packet Filter & NOC");
    ~X11Canvas();

    bool init();
    void close();
    void handleResize(int newWidth, int newHeight);

    int width() const { return m_width; }
    int height() const { return m_height; }
    Display* display() const { return m_display; }
    Window window() const { return m_window; }

    // Rendering Frame Control
    void beginFrame();
    void endFrame();

    // Drawing Primitives
    void clear(const Color &c);
    void fillRect(int x, int y, int w, int h, const Color &c);
    void drawRect(int x, int y, int w, int h, const Color &c, int lineWidth = 1);
    void fillRoundedRect(int x, int y, int w, int h, int radius, const Color &c);
    void drawRoundedRect(int x, int y, int w, int h, int radius, const Color &c, int lineWidth = 1);
    void drawLine(int x1, int y1, int x2, int y2, const Color &c, int lineWidth = 1);
    void drawText(int x, int y, const std::string &text, const Color &c, int fontSize = 12, bool bold = false);
    void drawTextCentered(int x, int y, int w, int h, const std::string &text, const Color &c, int fontSize = 12, bool bold = false);
    void drawCard(int x, int y, int w, int h, const std::string &title, const Color &bg, const Color &border);
    void drawProgressBar(int x, int y, int w, int h, double progress, const Color &fillColor, const Color &bgColor);
    void drawPillBadge(int x, int y, int w, int h, const std::string &text, const Color &fillColor, const Color &textColor, bool bold = true);

    // Font measurement
    int getTextWidth(const std::string &text, int fontSize = 12, bool bold = false);

private:
    int m_width;
    int m_height;
    std::string m_title;

    Display *m_display;
    Window m_window;
    int m_screen;
    GC m_gc;
    Pixmap m_backBuffer;
    XftDraw *m_xftDraw;

    XftFont *m_fontRegular;
    XftFont *m_fontBold;
    XftFont *m_fontLarge;
    XftFont *m_fontSmall;

    std::unordered_map<uint32_t, XftColor> m_xftColorCache;

    XftColor getXftColor(const Color &c);
    unsigned long getX11Color(const Color &c);
};

} // namespace netguard

#endif // NETGUARD_X11_CANVAS_HPP
