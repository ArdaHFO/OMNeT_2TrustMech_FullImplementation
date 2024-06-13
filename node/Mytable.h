#ifndef MYTABLE_H_
#define MYTABLE_H_

#include <vector>
#include <string>

class MyTable {
private:
    std::vector<int> nodeList; // List of node IDs

public:
    // Constructor
    MyTable() {}

    // Destructor
    ~MyTable() {}

    // Function to add a node to the table
    void addNode(int nodeId) {
        nodeList.push_back(nodeId);
    }

    // Function to return the table as a string
    std::string getTableAsString() {
        std::string tableString = "Node List:\n";
        for (int nodeId : nodeList) {
            tableString += "Node ID: " + std::to_string(nodeId) + "\n";
        }
        return tableString;
    }
};

#endif /* MYTABLE_H_ */
