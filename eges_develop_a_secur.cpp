#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <map>
#include <regex>

using namespace std;

// Structure to represent a script
struct Script {
    string name;
    string code;
    vector<string> dependencies;
    vector<string> sensitiveFunctions;
};

// Function to parse script file
Script parseScript(const string& filename) {
    Script script;
    ifstream file(filename);
    string line;
    while (getline(file, line)) {
        if (line.find("name:") != string::npos) {
            script.name = line.substr(5);
        } else if (line.find("dependencies:") != string::npos) {
            script.dependencies.push_back(line.substr(12));
        } else if (line.find("sensitiveFunctions:") != string::npos) {
            script.sensitiveFunctions.push_back(line.substr(17));
        } else {
            script.code += line + "\n";
        }
    }
    return script;
}

// Function to analyze script for security vulnerabilities
void analyzeScript(const Script& script) {
    map<string, int> functionCallCount;
    regex regex("([a-zA-Z_][a-zA-Z_0-9]*)\\(.*\\);?");
    smatch match;
    for (string::const_iterator it = script.code.begin(); it != script.code.end(); ++it) {
        string token;
        while (it != script.code.end() && iscprint(*it)) {
            token += *it;
            ++it;
            if (it == script.code.end() || !iscprint(*it)) {
                break;
            }
        }
        if (regex_search(token, match, regex)) {
            string functionName = match[1];
            if (find(script.sensitiveFunctions.begin(), script.sensitiveFunctions.end(), functionName) != script.sensitiveFunctions.end()) {
                if (functionCallCount.find(functionName) != functionCallCount.end()) {
                    functionCallCount[functionName]++;
                } else {
                    functionCallCount[functionName] = 1;
                }
            }
        }
    }
    cout << "Script Analysis Report:" << endl;
    cout << "----------------------" << endl;
    for (auto& func : functionCallCount) {
        cout << "Function " << func.first << " called " << func.second << " times." << endl;
    }
}

int main() {
    Script script = parseScript("script.txt");
    analyzeScript(script);
    return 0;
}