#!/usr/bin/env python
##ImmunityHeader v1 
###############################################################################
## File       :  gaphas_extras.py
## Description:  Little bits of gaphas extension code that should be reusable 
##            :  lots of places
## Created_On :  Thu Aug 13 10:06:52 2009
## Created_By :  Rich
## Modified_On:  Thu Aug 20 14:46:33 2009
## Modified_By:  Rich
## Modified_On:  Tue Aug 14 11:03:20 2012
## Modified_By:  miguel
##
## (c) Copyright 2009, Immunity, Inc. all rights reserved.
###############################################################################
from gaphas import aspect
from gaphas import tool
from gaphas import item
from gaphas.item import NW, NE,SW, SE
from gaphas import examples
from gaphas import connector

##Easy access to percent RGB colour values
PALETTE = {}
PALETTE['black'] = (0, 0, 0)
PALETTE['white'] = (1, 1, 1)
PALETTE['red'] = (1, 0, 0)
PALETTE['red2'] = (0.89, 0.18, 0.19)
PALETTE['green'] = (0, 0.8, 0.4)
PALETTE['blue'] = (0.01, 0.46, 0.99)
PALETTE['cyan'] = (0.01, 0.90, 0.99)
PALETTE['purple'] = (0.75, 0.24, 1)
PALETTE['pink'] = (1, 0.5, 0.5)
PALETTE['orange'] = (0.89, 0.51, 0.09) 
PALETTE['teal'] = ( 0.4, 0.9, 0.9)
PALETTE['coffee'] = (0.45, 0.24, 0.1) 
PALETTE['yellow'] = (1.0, 1.0, 0.0) 

def connect_port(item, line, handle, port):
    line.pos = port.point
    conn = aspect.Connector(line, handle)
    sink = aspect.ConnectionSink(item, port)
    conn.connect(sink)

def connect_nodes(view, parent, child):
    """
    Take two gaphas objects (NodeItems) and connect them with a line.
    IN  : view - the gphas view we are operating in
          parent - gaphas object to join
          child - gaphas object to join
    OUT : connector - gpahas object joining the parent & child
    """
    ##Add a line to the gaphas canvas
    connector = ConnectorItem(colour=parent.node_colour)
    head      = connector.handles()[0]
    tail      = connector.handles()[-1]
    view.canvas.add(connector)
    
    # connect to parent source port dest port
    connect_port(parent, connector, head, parent._sport)
    
    # connect to child dest port
    connect_port(child, connector, tail, child._dport)
    
    return connector

class ConnectorItem(item.Line):
    """
    A line to connect our gaphas objects together with, pretty helpful when 
    building connected graphs
    """
    def __init__(self, colour=(1, 0, 0), head=False, tail=False):
        """
        Just set our line colour to be the same as our parent
        IN  : colour - default percent rgb values to use for line - tuple
              head - draw arrow head on the line - boolean
              tail - draw arrow tail on the line - boolean
        OUT : N/A
        """
        super(ConnectorItem, self).__init__()
        
        self.is_connector     = True
        self.connector_colour = colour
        
        self.handles()[0].visible = False
        self.handles()[-1].visible = False
        
        if head:
            self.draw_head = self.do_draw_head
        if tail:
            self.draw_tail = self.do_draw_tail

    def draw(self, context):
        """
        Actually stroke the line via cairo
        IN  : gaphas context
        OUT : None
        """
        cr = context.cairo
        cr.set_source_rgba(*(self.connector_colour + (1,)))
        super(ConnectorItem, self).draw(context)
    
    def do_draw_head(self, context):
        cr = context.cairo
        cr.move_to(0, 0)
        cr.line_to(10, 10)
        cr.stroke()
        # Start point for the line to the next handle
        cr.move_to(0, 0)

    def do_draw_tail(self, context):
        cr = context.cairo
        cr.line_to(0, 0)
        cr.line_to(10, 10)
        cr.stroke()

class ConnectableCircle(examples.Circle):
    """
    A Circle object with a PointPort at 12 'o' clock and 6 'o' clock
    """
    def __init__(self, radius, offset = 0):
        """
        Call into the standards circle constructor and then create PointPorts
        IN  : offset - How much to displace the line from the nodes - int
        OUT : None
        """
        super(ConnectableCircle, self).__init__()
        self.radius = radius
        ##Code for connection ports

        ##Port on bottom of circle for connections
        self._sport = connector.PointPort(connector.Position((self._handles[0].x, self.radius + offset)))
        ##Port on top of circle for connections
        self._dport = connector.PointPort(connector.Position((self._handles[0].x, -self.radius - offset)))

        self._ports.append(self._sport)
        self._ports.append(self._dport)
        
        self.node_colour = PALETTE['black']
