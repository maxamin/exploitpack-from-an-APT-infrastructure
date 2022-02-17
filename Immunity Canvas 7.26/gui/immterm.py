#!/usr/bin/env python
#
# A GTK Terminal widget to present things nicely.
#
#  -- Ronald Huizer
#
# vim: sw=4 ts=4 expandtab

try:
    import os
    import gtk
    import gobject
    import pango
    import cairo
    import pangocairo
    from gtk import gdk
except:
    raise SystemExit

import logging


# Attributes for every terminal character we display
class ImmTermCharAttributes:
    def __init__(self):
        self.bold = 0
        # default foreground as chosen by konsole
        self.foreground_color = ImmTermColor(178, 178, 178)
        self.background_color = ImmTermColor()
        self.underline = 0
        self.strikethrough = 0
        self.reverse = 0
        self.blink = 0

    def set_foreground_color(self, r, g, b):
        self.foreground_color.set(r, g, b)

    def set_background_color(self, r, g, b):
        self.background_color.set(r, g, b)

# Represents a single terminal character
class ImmTermChar:
    def __init__(self, value):
        self.attributes = ImmTermCharAttributes()
        self.value = value

    def set_foreground_color(self, r, g, b):
        """
        Sets the foreground color of this terminal character to
        the RGB value specified.
        """
        self.attributes.set_foreground_color(r, g, b)

    def set_background_color(self, r, g, b):
        """
        Sets the background color of this terminal character to
        the RGB value specified.
        """
        self.attributes.set_background_color(r, g, b)

class ImmTermColor:
    def __init__(self, r = 0, g = 0, b = 0):
        self.red = r
        self.green = g
        self.blue = b

    def get(self):
        return self.red, self.green, self.blue

    def get_cairo(self):
        return self.red / 256.0, self.green / 256.0, self.blue / 256.0

    def set(self, r, g, b):
        (self.red, self.green, self.blue) = (r, g, b)

class ImmTermFontInfo:
    def __init__(self, pango_ctx):
        self.layout = pango.Layout(pango_ctx)
        self.measure_font()

    def measure_font(self):
        # dummy fixed width character we be working with.
        self.layout.set_text("X")
        # get the logical extents
        extents = self.layout.get_extents()[1]
        # logical extent width
        self.width = pango.PIXELS(extents[2])
        # logical extent height
        self.height = pango.PIXELS(extents[3])
        self.ascent = pango.PIXELS(self.layout.get_iter().get_baseline())

class ImmTerm(gtk.DrawingArea):
    __gsignals__ = {
        "expose_event": "override",
        "size_request": "override"
    }

    def __init__(self, width = 80, height = 24, scale = True):
        # Widget super class initialization
        gtk.DrawingArea.__init__(self)

        # By default a GTK DrawingArea is not focussable, so we
        # cannot get key-pressed-events.  Make it work.
        self.set_flags(gtk.CAN_FOCUS)

        # Cairo surface for Immunity CANVAS logo
        self.logo = cairo.ImageSurface.create_from_png(
            os.path.join(
                os.path.dirname(__file__),
                "pixmaps/canvas_spray_trans.png"
            )
        )

        # Flag that controls terminal resizing.  If set, the
        # height and width of the terminal will be adjusted dependent
        # on the allocated terminal size.
        self.scale_flag = scale

        # Initialize terminal width and height
        self.data = None
        if not self.scale_flag:
            self.resize(width, height)

        # Cursor starts at position (x, y) = (0, 0)
        self.cursor_pos = [0, 0]

        # Connect keyboard events
        self.connect('key-press-event', self.key_press_event)

        # Initialize pango environment -- we do this immediatly,
        # as in order to determine the space needed for this widget
        # we need to know the font metrics that we will be using.
        self.pango_ctx = self.get_pango_context()

        # Base direction for bidirectional fonts is left to right.
        self.pango_ctx.set_base_dir(pango.DIRECTION_LTR)

        # If necessary set up options for our font context
        if pangocairo.context_get_font_options(self.pango_ctx) == None:
            opts = cairo.FontOptions()
            pangocairo.context_set_font_options(self.pango_ctx, opts)

        # Create the pango layout object using the context
        self.font_info = ImmTermFontInfo(self.pango_ctx)

        # Set up the default font
        self.set_font()

        # Global terminal attributes.  These will be used for new
        # text that is added to the terminal.
        self.attributes = ImmTermCharAttributes()

        # Initialize the event handler dictionary.
        self.event_handlers = {
            "newline-input-event": None,
        }

        # Input buffer used to handle newline events.  We track
        # input events for the newline-input-event handler here.
        self.input_buffer = ""
        self.input_pos = 0

    def resize(self, width, height):
        """
        Resize the current terminal.  We mimick the behaviour of
        common terminals here, allowing the terminal to grow, but
        not sizing it down in order to keep all characters in
        memory.
        However, ImmTerm will not dynamically rewrap the input line.
        """
        # Initialize the terminal character raster
        if self.data == None:
            self.width = width
            self.height = height
            self.data = [[ImmTermChar(0) for i in xrange(width)]    \
                                         for j in xrange(height)]
            return

        # Handle height resize
        if height < self.height:
            for i in xrange(self.height - height):
                if self.cursor_pos[1] == height - 1:
                    self.data.pop(0)
                else:
                    self.data.pop(len(self.data) - 1)
            if self.cursor_pos[1] >= height:
                self.cursor_pos[1] = height - 1
        elif height > self.height:
            for j in xrange(self.height, height):
                self.data.append([])
                for i in xrange(self.width):
                    self.data[j].append(ImmTermChar(0))

        # height has been resized
        self.height = height

        # Handle width resize
        if width > self.width:
            for j in xrange(self.height):
                for i in xrange(self.width, width):
                    self.data[j].append(ImmTermChar(0))

        # width has been resized
        self.width = width

        # XXX: expensive, can be optimized
        if self.window:
            self.window.invalidate_rect(self.allocation,True)

    def set_font(self):
        # Create a Monospace font description
        self.font_desc = pango.FontDescription('Monospace')
        self.font_info.layout.set_font_description(self.font_desc)
        logging.info("Immunity terminal: using font: %s" % self.font_desc.to_string())

    def do_realize(self):
        """
        Overrides the gtk.DrawingArea widget realization method.
        """
        gtk.DrawingArea.do_realize(self)

    def do_size_request(self, requisition):
        """
        From Widget.py: The do_size_request method Gtk+ is calling
        on a widget to ask it the widget how large it wishes to be.
        It's not guaranteed that gtk+ will actually give this size
        to the widget.
        """
        if self.scale_flag:
            requisition.width = 0
            requisition.height = 0
        else:
            requisition.width = self.width * self.get_font_width()
            requisition.height = self.height * self.get_font_height()

    def do_size_allocate(self, allocation):
        """
        The do_size_allocate is called by when the actual
        size is known and the widget is told how much space
        could actually be allocated Save the allocated space
        self.allocation = allocation. The following code is
        identical to the widget.py example"""

        self.allocation = allocation

        if self.scale_flag:
            self.resize(allocation.width / self.get_font_width(),
                        allocation.height / self.get_font_height())

        if self.flags() & gtk.REALIZED:
            self.window.move_resize(*allocation)

    def get_font_height(self):
        return self.font_info.height

    def get_font_width(self):
        return self.font_info.width

    def get_font_ascent(self):
        return self.font_info.ascent

    def set_char(self, ch, x, y):
        self.data[y][x].value = ch
        self.data[y][x].set_foreground_color(*self.attributes.foreground_color.get())
        self.data[y][x].set_background_color(*self.attributes.background_color.get())

        if self.window:
            self.cell_draw(x, y)

    def set_line(self, line, lineno):
        for i in xrange(0, min(len(line), self.width)):
            self.data[lineno][i].value = line[i]
            self.data[lineno][i].set_foreground_color(*self.attributes.foreground_color.get())
            self.data[lineno][i].set_background_color(*self.attributes.background_color.get())

        if self.window:
            self.line_draw(lineno)

    def line_output(self, line, input = False):
        """
        Writes a line to the terminal at the current cursor position,
        wrapping lines if necessary.
        """
        for i in xrange(len(line)):
            if line[i] == '\r':
                self.carriage_return()
            elif line[i] == '\n':
                self.carriage_return()
                self.line_feed()
            else:
                x, y = self.cursor_pos
                self.data[y][x].value = line[i]
                self.data[y][x].set_foreground_color(*self.attributes.foreground_color.get())
                self.data[y][x].set_background_color(*self.attributes.background_color.get())
                # The cursor already invalidates the rectangles.
                self.cursor_forward()

        if not input:
            # Initialize the rest of the line to its defaults.
            for i in xrange(self.cursor_pos[0], self.width):
                self.data[self.cursor_pos[1]][i].value = 0
                self.data[self.cursor_pos[1]][i].attributes = ImmTermCharAttributes()

            # Update possibly zeroed rest of the line.
            self.line_draw(self.cursor_pos[1])

    def do_expose_event(self, event):
        """This is where the widget must draw itself."""

        self.cairo = self.window.cairo_create()

        # Initialize the clipping plane
        self.cairo.rectangle(event.area.x, event.area.y,
                        event.area.width, event.area.height)
        self.cairo.clip()

        # make sure the entire allocated background is filled
        self.cairo.set_source_rgb(0, 0, 0)
        self.cairo.rectangle(*self.allocation)
        self.cairo.fill()

        # cache the font dimensions
        fwidth = self.get_font_width()
        fheight = self.get_font_height()
        fascent = self.get_font_ascent()

        # determine x, y, w, h we want to rework
        eax = event.area.x / fwidth
        eay = event.area.y / fheight
        eaw = (event.area.width + fwidth - 1) / fwidth
        eah = (event.area.height + fheight - 1) / fheight

        # draw the background dependent on character attributes
        for y in xrange(eay, min(eay + eah, self.height)):
            for x in xrange(eax, min(eax + eaw, self.width)):
                self.cairo.set_source_rgb(*self.data[y][x].attributes.background_color.get_cairo())
                self.cairo.rectangle(x * fwidth, y * fheight, fwidth, fheight)
                self.cairo.fill()

        # draw the logo
        self.cairo.set_source_surface(self.logo,
            self.allocation.width / 2 - self.logo.get_width() / 2,
            self.allocation.height / 2 - self.logo.get_height() / 2)
        self.cairo.paint_with_alpha(0.3)

        # draw the text with the draw_layout method
        for y in xrange(eay, min(eay + eah, self.height)):
            for x in xrange(eax, min(eax + eaw, self.width)):
                if self.data[y][x].value != 0:
                    # set the foreground color
                    self.cairo.set_source_rgb(*self.data[y][x].attributes.foreground_color.get_cairo())
                    self.font_info.layout.set_text(self.data[y][x].value)
                    self.cairo.move_to(x * fwidth, y * fheight + fascent)
                    self.cairo.show_layout_line(self.font_info.layout.get_line(0))

        self.draw_cursor(cairo, self.cursor_pos[0], self.cursor_pos[1])

        return False

    def key_press_event(self, widget, event):
        """
        Default key event handler.  This implements default terminal
        behaviour.   In case different behaviour is needed, this
        function should be overridden.
        """
        if event.keyval == gtk.keysyms.Left:
            # Allow navigating up and down the input buffer with the cursor
            if self.input_pos != 0:
                self.cursor_backward()
                self.input_pos -= 1
        elif event.keyval == gtk.keysyms.Right:
            # Allow navigating up and down the input buffer with the cursor
            if self.input_pos < len(self.input_buffer):
                self.cursor_forward()
                self.input_pos += 1
#        elif event.keyval == gtk.keysyms.Up:
#            widget.cursor_up()
#        elif event.keyval == gtk.keysyms.Down:
#            widget.cursor_down()
        elif event.keyval == gtk.keysyms.Return:
            widget.newline_input()
        elif event.keyval == gtk.keysyms.BackSpace:
            self.cursor_backspace()
        elif event.keyval >= 0x20 and event.keyval <= 0x7E:
            # Add the character to the input buffer.
            self.input_buffer = self.input_buffer[:self.input_pos]      \
                                + chr(event.keyval)                     \
                                + self.input_buffer[self.input_pos:]
            # Handle insertion in the middle of the input buffer
            self.line_output(self.input_buffer[self.input_pos:], True)
            self.cursor_backward(len(self.input_buffer) - self.input_pos - 1)
            self.input_pos += 1

        return True # do not propagate events further ...

    def draw_cursor(self, cairo, x, y):
        # set the cursor foreground color to the one of the character
        # we are on.
        self.cairo.set_source_rgb(*self.data[y][x].attributes.foreground_color.get_cairo())

        self.cairo.rectangle(x * self.get_font_width(), y * self.get_font_height(),
            self.get_font_width(), self.get_font_height())
        self.cairo.fill()

        # repaint the letter that was here using the background color
        if self.data[y][x].value != 0:
            self.cairo.set_source_rgb(*self.data[y][x].attributes.background_color.get_cairo())
            self.cairo.move_to(x * self.get_font_width(), y * self.get_font_height() + self.get_font_ascent())
            self.font_info.layout.set_text(self.data[y][x].value)
            self.cairo.show_layout_line(self.font_info.layout.get_line(0))

    def connect_event(self, event, handler):
        """
        Connects the terminal event handler with the terminal event.
        This function does not override connect in order to let GTK
        have its own event namespace.
        """
        self.event_handlers[event] = handler

    def newline_input(self):
        """
        Performs a carriage return and a line feed in the terminal.
        Calls the newline-input-event handler.
        """
        # Compensate for being in the middle of the input buffer
        self.cursor_forward(len(self.input_buffer) - self.input_pos)
        # Output a CR|LF pair first, and then pass control to the
        # handler.
        self.carriage_return()
        self.line_feed()

        if self.event_handlers["newline-input-event"] != None:
            self.event_handlers["newline-input-event"](self, self.input_buffer)

        # We're done with the input buffer
        self.input_buffer = ""
        self.input_pos = 0

    def newline_output(self):
        """
        Performs a carriage return and a line feed in the terminal.
        """
        self.carriage_return()
        self.line_feed()

    def line_feed(self):
        """
        Performs a line feed in the terminal, scrolling the topmost
        line out, and creating an empty one on the bottom.
        """
        if self.cursor_pos[1] == self.height - 1:
            # Compensate the y-axis of a saved cursor position
            self.data.pop(0)
            self.data.append([ImmTermChar(0) for i in xrange(self.width)])
            self.draw()
        else:
            self.cursor_down()

    def carriage_return(self):
        """
        Sets the cursor back to the beginning of the line.
        """
        old_pos = tuple(self.cursor_pos)
        self.cursor_pos[0] = 0

        # invalidate the rectangles for the old and new cursor positions
        self.cell_draw(*old_pos)
        self.cell_draw(*self.cursor_pos)

    def set_font_color(self, r, g, b):
        """
        Set the current terminal font color to the RGB values
        specified.  All characters added to the terminal will use
        this color value.
        """
        self.attributes.foreground_color.red = r
        self.attributes.foreground_color.green = g
        self.attributes.foreground_color.blue = b

    def set_background_color(self, r, g, b):
        """
        Set the current terminal background color to the RGB values
        specified.  All characters added to the terminal will use
        this color value.
        """
        self.attributes.background_color.red = r
        self.attributes.background_color.green = g
        self.attributes.background_color.blue = b

    def set_bold(self):
        """
        Sets the bold attribute.
        """
        self.attributes.bold = True

    def cursor_left(self, count = 1):
        """
        Moves the cursor to the left.
        """
        old_pos = tuple(self.cursor_pos)
        if count >= self.cursor_pos[0]:
            self.cursor_pos[0] = 0
        else:
            self.cursor_pos[0] -= count

        # invalidate the rectangles for the old and new cursor positions
        self.cell_draw(*old_pos)
        self.cell_draw(*self.cursor_pos)

    def cursor_right(self, count = 1):
        """
        Moves the cursor to the right.
        """
        old_pos = list(self.cursor_pos)
        if count >= self.width - self.cursor_pos[0]:
            self.cursor_pos[0] = self.width - 1
        else:
            self.cursor_pos[0] += count

        # invalidate the rectangles for the old and new cursor positions
        self.cell_draw(*old_pos)
        self.cell_draw(*self.cursor_pos)

    def cursor_up(self, count = 1):
        """
        Moves the cursor up.
        """
        old_pos = list(self.cursor_pos)
        if count >= self.cursor_pos[1]:
            self.cursor_pos[1] = 0
        else:
            self.cursor_pos[1] -= count

        # invalidate the rectangles for the old and new cursor positions
        self.cell_draw(*old_pos)
        self.cell_draw(*self.cursor_pos)

    def cursor_down(self, count = 1):
        """
        Moves the cursor down.
        """
        old_pos = list(self.cursor_pos)
        if count >= self.height - self.cursor_pos[1]:
            self.cursor_pos[1] = self.height - 1
        else:
            self.cursor_pos[1] += count

        # invalidate the rectangles for the old and new cursor positions
        self.cell_draw(*old_pos)
        self.cell_draw(*self.cursor_pos)

    def cursor_forward(self, count = 1):
        """
        Moves the cursor forward by one position, taking line wrapping into
        account.
        """
        x, y = self.cursor_pos

        # Deal with a possibly short line first
        if count >= self.width - x:
            self.cursor_right(self.width - x)
            count -= self.width - x
            self.cursor_pos[0] = 0
            self.line_feed()

        for i in xrange(count / self.width):
            self.line_feed()
        self.cursor_right(count % self.width)

    def cursor_backward(self, count = 1):
        """
        Moves the cursor backward by one position, taking line wrapping into
        account.
        """
        # Short-circuit corner cases
        if count == 0:
            return

        # Deal with all multiples of the terminal width
        if count / self.width > 0:
            self.cursor_up(count / self.width)
            count = count % self.width

        # Deal with possible short line first
        if count > self.cursor_pos[0]:
            count -= self.cursor_pos[0] + 1
            self.cursor_left(self.cursor_pos[0])
            self.cursor_up()
            self.cursor_pos[0] = self.width - 1

        # And deal with the remainder
        if count > 0:
            self.cursor_left(count)

    def cursor_backspace(self):
        """
        Moves the cursor a step backwards, taking line wrapping into account.
        """
        if self.input_pos == 0:
            return

        self.input_buffer = self.input_buffer[:self.input_pos - 1] +    \
                            self.input_buffer[self.input_pos:]
        self.input_pos -= 1
        self.cursor_backward()
        old_pos = list(self.cursor_pos)
        self.line_output(self.input_buffer[self.input_pos:])
        self.cursor_pos = old_pos

    def cursor_get(self):
        """
        Returns the cursor position as an (x, y) tuple.
        """
        return self.cursor_pos

    def cursor_set(self, x, y):
        self.cell_draw(*self.cursor_pos)
        self.cursor_pos = [x, y]
        self.cell_draw(*self.cursor_pos)

    def cell_draw(self, x, y):
        """
        Redraw a cell of the terminal at pixel positions [x, y].
        """
        if self.window:
            w = self.get_font_width()
            h = self.get_font_height()
            self.window.invalidate_rect((x * w, y * h, w, h), True)

    def line_draw(self, y):
        """
        Redraw a line of the terminal at position y.
        """
        if self.window:
            w = self.get_font_width()
            h = self.get_font_height()
            self.window.invalidate_rect((0, y * h, w * self.width, h), True)

    def draw(self):
        """
        Redraw the terminal.  Expensive.
        """
        if self.window:
            self.window.invalidate_rect(self.allocation, True)

if __name__ == "__main__":
    def newline_event(term, s):
        print s
        if s == "id":
            term.line_output("uid=0(root) gid=0(root) groups=0(root)\n")

    # register the class as a Gtk widget
    gobject.type_register(ImmTerm)

    window = gtk.Window()
    window.connect('delete-event', gtk.main_quit)
    term = ImmTerm(80, 24, False)

    window.add(term)
    window.show_all()

    term.set_font_color(255, 0, 0)
    term.line_output("                                                               __\n")
    term.line_output("                                                        ____  /  \\\n")
    term.line_output("                                                       /    \\ \\__/\n")
    term.line_output("                                                      /      \\ _______\n")
    term.line_output("  ________  ______  ____   _ _   _ _____ _______   __ \\      //       \\\n")
    term.line_output(" |_   _|  \\/  ||  \\/  | | | | \\ | |_   _|_   _\\ \\ / /  \\____//         \\\n")
    term.line_output("   | | | .  . || .  . | | | |  \\| | | |   | |  \\ V /        /           \\\n")
    term.line_output("   | | | |\\/| || |\\/| | | | | . ` | | |   | |   \\ /         \\           /\n")
    term.line_output("  _| |_| |  | || |  | | |_| | |\\  |_| |_  | |   | |          \\         /\n")
    term.line_output("  \\___/\\_|  |_/\\_|  |_/\\___/\\_| \\_/\\___/  \\_/   \\_/           \\_______/\n")
    term.cursor_down(3)
#    term.set_background_color(0, 255, 0)
#    term.set_font_color(0, 0, 255)
#    term.set_line(r"                          Hello World, this is a retarded test!", 15)
#    term.set_background_color(0, 0, 0)
#    term.set_font_color(178, 178, 178)
    term.connect_event("newline-input-event", newline_event)

    gtk.main()
