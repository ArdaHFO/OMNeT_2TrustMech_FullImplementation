//==========================================================================
//  NETBUILDER.CC - part of
//
//                     OMNeT++/OMNEST
//            Discrete System Simulation in C++
//
//==========================================================================

/*--------------------------------------------------------------*
  Copyright (C) 1992-2015 Andras Varga

  This file is distributed WITHOUT ANY WARRANTY. See the file
  `license' for details on this and other legal matters.
*--------------------------------------------------------------*/

#include <iostream>
#include <fstream>
#include <vector>
#include <string.h>
#include <omnetpp.h>




using namespace omnetpp;


class NetBuilder : public cSimpleModule
{
private:

  protected:
    void connect(cGate *src, cGate *dest, double delay, double ber, double datarate);
    void buildNetwork(cModule *parent);
    virtual void initialize() override;
    virtual void handleMessage(cMessage *msg) override;
    void someFunction();

};
Define_Module(NetBuilder);







void NetBuilder::initialize()
{
    //**************************************************
    //**************************************************

    cTextFigure *distanceDisplay;
    cCanvas *canvas = getParentModule()->getCanvas();
    distanceDisplay = check_and_cast<cTextFigure *>(canvas->getFigureByPath("status.distance"));
    double param1;
        param1=32;
    char buf[20];
    sprintf(buf, "%.0fm", param1);
    distanceDisplay->setText(buf);


    //**************************************************
    //**************************************************
    scheduleAt(0, new cMessage());
}

void NetBuilder::handleMessage(cMessage *msg)
{


    if (!msg->isSelfMessage())
        throw cRuntimeError("This module does not process messages.");

    delete msg;
    buildNetwork(getParentModule());
}

void NetBuilder::connect(cGate *src, cGate *dest, double delay, double ber, double datarate)
{
    cDatarateChannel *channel = nullptr;
    if (delay > 0 || ber > 0 || datarate > 0) {
        channel = cDatarateChannel::create("channel");
        if (delay > 0)
            channel->setDelay(delay);
        if (ber > 0)
            channel->setBitErrorRate(ber);
        if (datarate > 0)
            channel->setDatarate(datarate);
    }
    src->connectTo(dest, channel);
}

void NetBuilder::buildNetwork(cModule *parent)
{
    std::map<long, cModule *> nodeid2mod;
    std::string line;

    std::fstream nodesFile(par("nodesFile").stringValue(), std::ios::in);
    while (getline(nodesFile, line, '\n')) {
        if (line.empty() || line[0] == '#')
            continue;

        std::vector<std::string> tokens = cStringTokenizer(line.c_str()).asVector();
        if (tokens.size() != 3)
            throw cRuntimeError("wrong line in module file: 3 items required, line: \"%s\"", line.c_str());

        // get fields from tokens
        long nodeid = atol(tokens[0].c_str());
        const char *name = tokens[1].c_str();
        const char *modtypename = tokens[2].c_str();
        EV << "NODE id=" << nodeid << " name=" << name << " type=" << modtypename << "\n";

        // create module
        cModuleType *modtype = cModuleType::find(modtypename);
        if (!modtype)
            throw cRuntimeError("module type `%s' for node `%s' not found", modtypename, name);
        cModule *mod = modtype->create(name, parent);
        nodeid2mod[nodeid] = mod;

        // read params from the ini file, etc
        mod->finalizeParameters();
    }

    // read and create connections
    std::fstream connectionsFile(par("connectionsFile").stringValue(), std::ios::in);
    while (getline(connectionsFile, line, '\n')) {
        if (line.empty() || line[0] == '#')
            continue;
        std::vector<std::string> tokens = cStringTokenizer(line.c_str()).asVector();
        if (tokens.size() != 5)
            throw cRuntimeError("wrong line in parameters file: 5 items required, line: \"%s\"", line.c_str());

        // get fields from tokens
        long srcnodeid = atol(tokens[0].c_str());
        long destnodeid = atol(tokens[1].c_str());
        double delay = tokens[2] != "-" ? atof(tokens[2].c_str()) : -1;
        double error = tokens[3] != "-" ? atof(tokens[3].c_str()) : -1;
        double datarate = tokens[4] != "-" ? atof(tokens[4].c_str()) : -1;

        if (nodeid2mod.find(srcnodeid) == nodeid2mod.end())
            throw cRuntimeError("wrong line in connections file: node with id=%ld not found", srcnodeid);
        if (nodeid2mod.find(destnodeid) == nodeid2mod.end())
            throw cRuntimeError("wrong line in connections file: node with id=%ld not found", destnodeid);

        cModule *srcmod = nodeid2mod[srcnodeid];
        cModule *destmod = nodeid2mod[destnodeid];

        cGate *srcIn, *srcOut, *destIn, *destOut;
        srcmod->getOrCreateFirstUnconnectedGatePair("port", false, true, srcIn, srcOut);
        destmod->getOrCreateFirstUnconnectedGatePair("port", false, true, destIn, destOut);

        // connect
        connect(srcOut, destIn, delay, error, datarate);
        connect(destOut, srcIn, delay, error, datarate);
    }

    // initialization will simply skip already-initialized modules instead of causing error
    parent->callInitialize();
}

