#include <clang/Tooling/CommonOptionsParser.h>
#include <clang/Tooling/Tooling.h>
#include <clang/ASTMatchers/ASTMatchers.h>
#include <clang/Frontend/FrontendActions.h>
#include <clang/Frontend/CompilerInstance.h>
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/AST/Stmt.h>
#include <clang/AST/Expr.h>
#include <clang/AST/Type.h>
#include <clang/AST/Decl.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Support/CommandLine.h>
#include <fstream>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <string>
#include <sstream>
#include <iostream>
#include <filesystem>
#include <random>
#include <chrono>
#include <curl/curl.h>
#include <json.hpp>

using namespace clang;
using namespace clang::tooling;
using namespace clang::ast_matchers;
using json = nlohmann::json;

// Command line options
static llvm::cl::OptionCategory CppScannerCategory("cpp-scanner options");
static llvm::cl::opt<bool> SaveLocal("local", 
    llvm::cl::desc("Save output locally instead of uploading"),
    llvm::cl::cat(CppScannerCategory));
static llvm::cl::opt<std::string> OutputPath("output", 
    llvm::cl::desc("Output file path"), 
    llvm::cl::value_desc("filename"),
    llvm::cl::cat(CppScannerCategory));
static llvm::cl::opt<std::string> ApiEndpoint("endpoint", 
    llvm::cl::desc("API endpoint URL"), 
    llvm::cl::value_desc("url"),
    llvm::cl::cat(CppScannerCategory));

// Global configuration
static std::string apiEndpoint = "http://localhost:8080/api/scan";
static bool saveLocal = false;
static std::string outputPath = "../../output/codegraph_cpp.json";

// Global state
json codeGraph;
int nextId = 1;
std::unordered_map<const void*, int> nodeIds;
std::unordered_map<std::string, int> variableToNodeId;

// Statistics counters
int methodCalls = 0, assignments = 0, stringLiterals = 0, controlFlowNodes = 0;

// Vulnerability detection sets
std::unordered_set<std::string> taintSourceFunctions = {
    "scanf", "fscanf", "gets", "fgets", "getline", "read", "recv", "recvfrom", 
    "getenv", "gethostbyname", "accept", "cin"
};
std::unordered_set<std::string> taintSinkFunctions = {
    "system", "exec", "execl", "execv", "popen", "fopen", "send", "sendto",
    "strcpy", "strcat", "sprintf", "vsprintf", "mysql_query", "sqlite3_exec"
};
std::unordered_set<std::string> dangerousFunctions = {
    "gets", "strcpy", "strcat", "sprintf", "vsprintf", "strncpy", "strncat"
};
std::unordered_set<std::string> memoryFunctions = {
    "malloc", "calloc", "realloc", "free", "new", "delete"
};

// Utility functions
std::string generateUUID() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 15);
    std::stringstream ss;
    ss << std::hex;
    for (int i = 0; i < 8; ++i) ss << dis(gen);
    ss << "-";
    for (int i = 0; i < 4; ++i) ss << dis(gen);
    ss << "-4";
    for (int i = 0; i < 3; ++i) ss << dis(gen);
    ss << "-a";
    for (int i = 0; i < 3; ++i) ss << dis(gen);
    ss << "-";
    for (int i = 0; i < 12; ++i) ss << dis(gen);
    return ss.str();
}

int getNextId() {
    return nextId++;
}

std::string getExprString(const Expr* expr, ASTContext* context) {
    if (!expr) return "";
    std::string result;
    llvm::raw_string_ostream stream(result);
    expr->printPretty(stream, nullptr, context->getPrintingPolicy());
    return stream.str();
}

std::string getStringLiteralValue(const StringLiteral* SL) {
    if (!SL) return "";
    try {
        // Check if it's a regular char string
        if (SL->getCharByteWidth() == 1) {
            return SL->getString().str();
        } else {
            // Handle wide strings, UTF-16, UTF-32 etc.
            return "WIDE_STRING_LITERAL";
        }
    } catch (...) {
        return "STRING_LITERAL";
    }
}

json createEdge(int source, int target, const std::string& type) {
    json edge;
    edge["source"] = source;
    edge["target"] = target;
    edge["type"] = type;
    return edge;
}

class CodeGraphVisitor : public RecursiveASTVisitor<CodeGraphVisitor> {
public:
    explicit CodeGraphVisitor(ASTContext* Context) : Context(Context) {
        codeGraph["scanId"] = generateUUID();
        codeGraph["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        codeGraph["nodes"] = json::array();
        codeGraph["edges"] = json::array();
    }

    bool VisitTranslationUnitDecl(TranslationUnitDecl* TU) {
        SourceManager& SM = Context->getSourceManager();
        if (auto FE = SM.getFileEntryRefForID(SM.getMainFileID())) {
            json fileNode;
            int fileId = getNextId();
            fileNode["id"] = fileId;
            fileNode["type"] = "FILE";
            fileNode["name"] = FE->getName().str();
            codeGraph["nodes"].push_back(fileNode);
            nodeIds[TU] = fileId;
            currentFileId = fileId;
        }
        return true;
    }

    bool VisitFunctionDecl(FunctionDecl* Function) {
        if (!Function->hasBody() || isa<CXXMethodDecl>(Function)) return true;

        json functionNode;
        int functionId = getNextId();
        functionNode["id"] = functionId;
        functionNode["type"] = "METHOD";  // Using METHOD to match Java scanner
        functionNode["name"] = Function->getNameAsString();
        functionNode["returnType"] = Function->getReturnType().getAsString();
        functionNode["parameters"] = Function->getNumParams();
        
        codeGraph["nodes"].push_back(functionNode);
        codeGraph["edges"].push_back(createEdge(currentFileId, functionId, "CONTAINS"));
        nodeIds[Function] = functionId;
        currentMethodId = functionId;

        // Clear variable tracking for new function
        variableToNodeId.clear();

        // Process parameters
        for (const ParmVarDecl* Param : Function->parameters()) {
            processParameter(Param, functionId);
        }

        // Process function body
        if (Function->hasBody()) {
            processStatement(Function->getBody(), functionId);
        }

        return true;
    }

    bool VisitCXXMethodDecl(CXXMethodDecl* Method) {
        if (!Method->hasBody()) return true;

        json methodNode;
        int methodId = getNextId();
        methodNode["id"] = methodId;
        methodNode["type"] = "METHOD";
        methodNode["name"] = Method->getNameAsString();
        methodNode["returnType"] = Method->getReturnType().getAsString();
        methodNode["parameters"] = Method->getNumParams();

        codeGraph["nodes"].push_back(methodNode);
        if (currentClassId != -1) {
            codeGraph["edges"].push_back(createEdge(currentClassId, methodId, "CONTAINS"));
        } else {
            codeGraph["edges"].push_back(createEdge(currentFileId, methodId, "CONTAINS"));
        }
        nodeIds[Method] = methodId;
        currentMethodId = methodId;

        variableToNodeId.clear();

        for (const ParmVarDecl* Param : Method->parameters()) {
            processParameter(Param, methodId);
        }

        if (Method->hasBody()) {
            processStatement(Method->getBody(), methodId);
        }

        return true;
    }

    bool VisitCXXRecordDecl(CXXRecordDecl* Record) {
        if (!Record->isCompleteDefinition()) return true;

        json classNode;
        int classId = getNextId();
        classNode["id"] = classId;
        classNode["type"] = Record->isClass() ? "CLASS" : 
                          Record->isStruct() ? "CLASS" : "INTERFACE";
        classNode["name"] = Record->getNameAsString();

        codeGraph["nodes"].push_back(classNode);
        codeGraph["edges"].push_back(createEdge(currentFileId, classId, "CONTAINS"));
        nodeIds[Record] = classId;
        currentClassId = classId;

        // Process member variables
        for (const FieldDecl* Field : Record->fields()) {
            processField(Field, classId);
        }

        return true;
    }

private:
    ASTContext* Context;
    int currentFileId = -1;
    int currentClassId = -1;
    int currentMethodId = -1;

    void processParameter(const ParmVarDecl* Param, int functionId) {
        json paramNode;
        int paramId = getNextId();
        paramNode["id"] = paramId;
        paramNode["type"] = "PARAMETER";
        paramNode["name"] = Param->getNameAsString();
        paramNode["dataType"] = Param->getType().getAsString();

        codeGraph["nodes"].push_back(paramNode);
        codeGraph["edges"].push_back(createEdge(functionId, paramId, "DECLARES"));
        nodeIds[Param] = paramId;
        variableToNodeId[Param->getNameAsString()] = paramId;
    }

    void processField(const FieldDecl* Field, int classId) {
        json fieldNode;
        int fieldId = getNextId();
        fieldNode["id"] = fieldId;
        fieldNode["type"] = "FIELD";
        fieldNode["name"] = Field->getNameAsString();
        fieldNode["dataType"] = Field->getType().getAsString();

        codeGraph["nodes"].push_back(fieldNode);
        codeGraph["edges"].push_back(createEdge(classId, fieldId, "DECLARES"));
        nodeIds[Field] = fieldId;
    }

    void processStatement(const Stmt* S, int parentId) {
        if (!S) return;

        // Process different statement types
        if (const DeclStmt* DS = dyn_cast<DeclStmt>(S)) {
            for (const Decl* D : DS->decls()) {
                if (const VarDecl* VD = dyn_cast<VarDecl>(D)) {
                    processLocalVariable(VD, parentId);
                }
            }
        }
        else if (const CallExpr* CE = dyn_cast<CallExpr>(S)) {
            processMethodCall(CE, parentId);
        }
        else if (const CXXNewExpr* NE = dyn_cast<CXXNewExpr>(S)) {
            processObjectCreation(NE, parentId);
        }
        else if (const BinaryOperator* BO = dyn_cast<BinaryOperator>(S)) {
            if (BO->isAssignmentOp()) {
                processAssignment(BO, parentId);
            } else {
                processBinaryExpression(BO, parentId);
            }
        }
        else if (const StringLiteral* SL = dyn_cast<StringLiteral>(S)) {
            processStringLiteral(SL, parentId);
        }
        else if (const IfStmt* IS = dyn_cast<IfStmt>(S)) {
            processIfStatement(IS, parentId);
        }
        else if (const ForStmt* FS = dyn_cast<ForStmt>(S)) {
            processForLoop(FS, parentId);
        }
        else if (const WhileStmt* WS = dyn_cast<WhileStmt>(S)) {
            processWhileLoop(WS, parentId);
        }
        else if (const CXXForRangeStmt* FRS = dyn_cast<CXXForRangeStmt>(S)) {
            processForEachLoop(FRS, parentId);
        }
        else if (const CXXTryStmt* TS = dyn_cast<CXXTryStmt>(S)) {
            processTryStatement(TS, parentId);
        }
        else if (const ReturnStmt* RS = dyn_cast<ReturnStmt>(S)) {
            processReturnStatement(RS, parentId);
        }

        // Recursively process child statements
        for (auto it = S->child_begin(); it != S->child_end(); ++it) {
            processStatement(*it, parentId);
        }
    }

    void processLocalVariable(const VarDecl* VD, int parentId) {
        json varNode;
        int varId = getNextId();
        varNode["id"] = varId;
        varNode["type"] = "LOCAL_VARIABLE";
        varNode["name"] = VD->getNameAsString();
        varNode["dataType"] = VD->getType().getAsString();

        if (VD->hasInit()) {
            varNode["initializer"] = getExprString(VD->getInit(), Context);
            // Check for data flow from initializer
            checkDataFlow(VD->getInit(), varId);
        }

        codeGraph["nodes"].push_back(varNode);
        codeGraph["edges"].push_back(createEdge(parentId, varId, "DECLARES"));
        nodeIds[VD] = varId;
        variableToNodeId[VD->getNameAsString()] = varId;
    }

    void processMethodCall(const CallExpr* CE, int parentId) {
        json callNode;
        int callId = getNextId();
        callNode["id"] = callId;
        callNode["type"] = "METHOD_CALL";
        callNode["arguments"] = CE->getNumArgs();

        std::string functionName;
        if (const FunctionDecl* FD = CE->getDirectCallee()) {
            functionName = FD->getNameAsString();
        } else {
            functionName = getExprString(CE->getCallee(), Context);
        }
        callNode["name"] = functionName;

        // Check for vulnerabilities
        if (taintSourceFunctions.count(functionName)) {
            callNode["taintSource"] = true;
        }
        if (taintSinkFunctions.count(functionName)) {
            callNode["taintSink"] = true;
        }
        if (dangerousFunctions.count(functionName)) {
            callNode["dangerous"] = true;
            callNode["vulnerability"] = "BUFFER_OVERFLOW_RISK";
        }
        if (memoryFunctions.count(functionName)) {
            callNode["memoryOperation"] = true;
        }

        // Add scope if available
        if (const MemberExpr* ME = dyn_cast<MemberExpr>(CE->getCallee())) {
            callNode["scope"] = getExprString(ME->getBase(), Context);
        }

        codeGraph["nodes"].push_back(callNode);
        codeGraph["edges"].push_back(createEdge(parentId, callId, "INVOKES"));
        nodeIds[CE] = callId;
        methodCalls++;

        // Process arguments for data flow
        for (unsigned i = 0; i < CE->getNumArgs(); ++i) {
            processArgument(CE->getArg(i), callId);
        }
    }

    void processObjectCreation(const CXXNewExpr* NE, int parentId) {
        json objNode;
        int objId = getNextId();
        objNode["id"] = objId;
        objNode["type"] = "OBJECT_CREATION";
        objNode["className"] = NE->getAllocatedType().getAsString();
        
        if (NE->getNumPlacementArgs() > 0) {
            objNode["arguments"] = NE->getNumPlacementArgs();
        }

        codeGraph["nodes"].push_back(objNode);
        codeGraph["edges"].push_back(createEdge(parentId, objId, "INVOKES"));
        nodeIds[NE] = objId;

        // Process constructor arguments
        if (const CXXConstructExpr* CE = NE->getConstructExpr()) {
            for (unsigned i = 0; i < CE->getNumArgs(); ++i) {
                processArgument(CE->getArg(i), objId);
            }
        }
    }

    void processAssignment(const BinaryOperator* BO, int parentId) {
        json assignNode;
        int assignId = getNextId();
        assignNode["id"] = assignId;
        assignNode["type"] = "ASSIGNMENT";
        assignNode["target"] = getExprString(BO->getLHS(), Context);
        assignNode["value"] = getExprString(BO->getRHS(), Context);
        assignNode["operator"] = BinaryOperator::getOpcodeStr(BO->getOpcode()).str();

        codeGraph["nodes"].push_back(assignNode);
        codeGraph["edges"].push_back(createEdge(assignId, parentId, "CONTAINS_ASSIGNMENT"));
        nodeIds[BO] = assignId;
        assignments++;

        // Check data flow
        checkDataFlow(BO->getRHS(), assignId);
    }

    void processBinaryExpression(const BinaryOperator* BO, int parentId) {
        json exprNode;
        int exprId = getNextId();
        exprNode["id"] = exprId;
        exprNode["type"] = "BINARY_EXPRESSION";
        exprNode["operator"] = BinaryOperator::getOpcodeStr(BO->getOpcode()).str();
        exprNode["leftOperand"] = getExprString(BO->getLHS(), Context);
        exprNode["rightOperand"] = getExprString(BO->getRHS(), Context);

        codeGraph["nodes"].push_back(exprNode);
        codeGraph["edges"].push_back(createEdge(parentId, exprId, "CONTAINS_EXPRESSION"));
        nodeIds[BO] = exprId;
    }

    void processStringLiteral(const StringLiteral* SL, int parentId) {
        json stringNode;
        int stringId = getNextId();
        stringNode["id"] = stringId;
        stringNode["type"] = "STRING_LITERAL";
        stringNode["value"] = getStringLiteralValue(SL);
        stringNode["length"] = SL->getLength();

        // Check for SQL injection patterns
        std::string value = stringNode["value"];
        if (value.find("SELECT") != std::string::npos || 
            value.find("INSERT") != std::string::npos ||
            value.find("UPDATE") != std::string::npos ||
            value.find("DELETE") != std::string::npos) {
            stringNode["sqlPattern"] = true;
        }

        codeGraph["nodes"].push_back(stringNode);
        codeGraph["edges"].push_back(createEdge(parentId, stringId, "CONTAINS_LITERAL"));
        nodeIds[SL] = stringId;
        stringLiterals++;
    }

    void processIfStatement(const IfStmt* IS, int parentId) {
        json ifNode;
        int ifId = getNextId();
        ifNode["id"] = ifId;
        ifNode["type"] = "IF_STATEMENT";
        ifNode["condition"] = getExprString(IS->getCond(), Context);
        ifNode["hasElse"] = (IS->getElse() != nullptr);

        codeGraph["nodes"].push_back(ifNode);
        codeGraph["edges"].push_back(createEdge(parentId, ifId, "CONTAINS_CONTROL_FLOW"));
        nodeIds[IS] = ifId;
        controlFlowNodes++;
    }

    void processForLoop(const ForStmt* FS, int parentId) {
        json forNode;
        int forId = getNextId();
        forNode["id"] = forId;
        forNode["type"] = "FOR_LOOP";
        if (FS->getCond()) {
            forNode["condition"] = getExprString(FS->getCond(), Context);
        }

        codeGraph["nodes"].push_back(forNode);
        codeGraph["edges"].push_back(createEdge(parentId, forId, "CONTAINS_CONTROL_FLOW"));
        nodeIds[FS] = forId;
        controlFlowNodes++;
    }

    void processWhileLoop(const WhileStmt* WS, int parentId) {
        json whileNode;
        int whileId = getNextId();
        whileNode["id"] = whileId;
        whileNode["type"] = "WHILE_LOOP";
        whileNode["condition"] = getExprString(WS->getCond(), Context);

        codeGraph["nodes"].push_back(whileNode);
        codeGraph["edges"].push_back(createEdge(parentId, whileId, "CONTAINS_CONTROL_FLOW"));
        nodeIds[WS] = whileId;
        controlFlowNodes++;
    }

    void processForEachLoop(const CXXForRangeStmt* FRS, int parentId) {
        json forEachNode;
        int forEachId = getNextId();
        forEachNode["id"] = forEachId;
        forEachNode["type"] = "FOR_EACH_LOOP";
        forEachNode["variable"] = FRS->getLoopVariable()->getNameAsString();
        forEachNode["iterable"] = getExprString(FRS->getRangeInit(), Context);

        codeGraph["nodes"].push_back(forEachNode);
        codeGraph["edges"].push_back(createEdge(parentId, forEachId, "CONTAINS_CONTROL_FLOW"));
        nodeIds[FRS] = forEachId;
        controlFlowNodes++;
    }

    void processTryStatement(const CXXTryStmt* TS, int parentId) {
        json tryNode;
        int tryId = getNextId();
        tryNode["id"] = tryId;
        tryNode["type"] = "TRY_CATCH_BLOCK";
        tryNode["catchClausesCount"] = TS->getNumHandlers();
        tryNode["hasFinallyBlock"] = false; // C++ doesn't have finally

        json exceptionTypes = json::array();
        for (unsigned i = 0; i < TS->getNumHandlers(); ++i) {
            const CXXCatchStmt* catchStmt = TS->getHandler(i);
            if (const VarDecl* ExceptionDecl = catchStmt->getExceptionDecl()) {
                std::string exceptionType = ExceptionDecl->getType().getAsString();
                std::string exceptionName = ExceptionDecl->getNameAsString();
                
                json paramNode;
                int paramId = getNextId();
                paramNode["id"] = paramId;
                paramNode["type"] = "TYPE_CATCH_CALL";
                paramNode["name"] = exceptionName;
                paramNode["dataType"] = exceptionType;
                
                codeGraph["nodes"].push_back(paramNode);
                codeGraph["edges"].push_back(createEdge(tryId, paramId, "DECLARES"));
                variableToNodeId[exceptionName] = paramId;
                exceptionTypes.push_back(exceptionType);
            }
        }
        tryNode["exceptionTypes"] = exceptionTypes;

        codeGraph["nodes"].push_back(tryNode);
        codeGraph["edges"].push_back(createEdge(parentId, tryId, "CONTAINS_EXCEPTION_HANDLING"));
        nodeIds[TS] = tryId;
        controlFlowNodes++;
    }

    void processReturnStatement(const ReturnStmt* RS, int parentId) {
        json returnNode;
        int returnId = getNextId();
        returnNode["id"] = returnId;
        returnNode["type"] = "RETURN_STATEMENT";
        
        if (RS->getRetValue()) {
            returnNode["expression"] = getExprString(RS->getRetValue(), Context);
            checkDataFlow(RS->getRetValue(), returnId);
        }

        codeGraph["nodes"].push_back(returnNode);
        codeGraph["edges"].push_back(createEdge(parentId, returnId, "CONTAINS"));
        nodeIds[RS] = returnId;
    }

    void processArgument(const Expr* arg, int targetNodeId) {
        if (const DeclRefExpr* DRE = dyn_cast<DeclRefExpr>(arg)) {
            std::string varName = DRE->getNameInfo().getAsString();
            auto it = variableToNodeId.find(varName);
            if (it != variableToNodeId.end()) {
                codeGraph["edges"].push_back(createEdge(it->second, targetNodeId, "DATA_FLOW"));
            }
        }
        // Handle nested expressions recursively
        for (auto it = arg->child_begin(); it != arg->child_end(); ++it) {
            if (const Expr* childExpr = dyn_cast<Expr>(*it)) {
                processArgument(childExpr, targetNodeId);
            }
        }
    }

    void checkDataFlow(const Expr* expr, int targetNodeId) {
        if (!expr) return;
        
        if (const DeclRefExpr* DRE = dyn_cast<DeclRefExpr>(expr)) {
            std::string varName = DRE->getNameInfo().getAsString();
            auto it = variableToNodeId.find(varName);
            if (it != variableToNodeId.end()) {
                codeGraph["edges"].push_back(createEdge(it->second, targetNodeId, "DATA_FLOW"));
            }
        }
        
        // Recursively check child expressions
        for (auto it = expr->child_begin(); it != expr->child_end(); ++it) {
            if (const Expr* childExpr = dyn_cast<Expr>(*it)) {
                checkDataFlow(childExpr, targetNodeId);
            }
        }
    }
};

class CodeGraphConsumer : public ASTConsumer {
public:
    explicit CodeGraphConsumer(ASTContext* Context) : Visitor(Context) {}

    void HandleTranslationUnit(ASTContext& Context) override {
        Visitor.TraverseDecl(Context.getTranslationUnitDecl());
    }

private:
    CodeGraphVisitor Visitor;
};

class CodeGraphAction : public ASTFrontendAction {
public:
    std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance& CI, StringRef file) override {
        return std::make_unique<CodeGraphConsumer>(&CI.getASTContext());
    }
};

// HTTP upload callback
size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

bool uploadGraph(const json& graph, const std::string& endpoint) {
    CURL* curl = curl_easy_init();
    if (!curl) return false;

    std::string readBuffer;
    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "Authorization: Basic dXNlcjpzZWNyZXQ="); // user:secret

    std::string jsonData = graph.dump();
    
    curl_easy_setopt(curl, CURLOPT_URL, endpoint.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonData.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);

    CURLcode res = curl_easy_perform(curl);
    long response_code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res == CURLE_OK && response_code >= 200 && response_code < 300) {
        std::cout << "Code graph uploaded successfully to: " << endpoint 
                  << " with scanId: " << codeGraph["scanId"] << std::endl;
        return true;
    }
    std::cerr << "Failed to upload code graph: HTTP error code " << response_code << std::endl;
    return false;
}

void saveGraphLocally(const json& graph) {
    std::filesystem::path outputFile(outputPath);
    
    // Only create directories if the path has a parent directory
    if (outputFile.has_parent_path() && !outputFile.parent_path().empty()) {
        std::error_code ec;
        std::filesystem::create_directories(outputFile.parent_path(), ec);
        if (ec) {
            std::cerr << "Warning: Could not create directories: " << ec.message() << std::endl;
        }
    }
    
    std::ofstream outFile(outputFile);
    if (outFile.is_open()) {
        outFile << graph.dump(2);
        outFile.close();
        std::cout << "Code graph saved to: " << outputPath << std::endl;
    } else {
        std::cerr << "Could not write to: " << outputPath << std::endl;
    }
}

int main(int argc, const char** argv) {
    curl_global_init(CURL_GLOBAL_DEFAULT);

    auto ExpectedParser = CommonOptionsParser::create(argc, argv, CppScannerCategory);
    if (!ExpectedParser) {
        llvm::errs() << ExpectedParser.takeError();
        return 1;
    }
    CommonOptionsParser& OptionsParser = ExpectedParser.get();

    // Parse command line options
    if (SaveLocal.getValue()) saveLocal = true;
    if (!OutputPath.getValue().empty()) outputPath = OutputPath.getValue();
    if (!ApiEndpoint.getValue().empty()) apiEndpoint = ApiEndpoint.getValue();

    ClangTool Tool(OptionsParser.getCompilations(), OptionsParser.getSourcePathList());

    std::cout << "Scanning C/C++ files for code graph generation..." << std::endl;
    int result = Tool.run(newFrontendActionFactory<CodeGraphAction>().get());

    if (result == 0) {
        // Add statistics to the code graph
        json statistics;
        statistics["totalNodes"] = codeGraph["nodes"].size();
        statistics["totalEdges"] = codeGraph["edges"].size();
        statistics["methodCalls"] = methodCalls;
        statistics["assignments"] = assignments;
        statistics["stringLiterals"] = stringLiterals;
        statistics["controlFlowNodes"] = controlFlowNodes;
        
        codeGraph["statistics"] = statistics;
        
        // Add metadata
        codeGraph["language"] = "C++";
        codeGraph["tool"] = "cpp-scanner";
        codeGraph["version"] = "1.0.0";
        
        std::cout << "Scan completed successfully:" << std::endl;
        std::cout << "  - Total nodes: " << statistics["totalNodes"] << std::endl;
        std::cout << "  - Total edges: " << statistics["totalEdges"] << std::endl;
        std::cout << "  - Method calls: " << methodCalls << std::endl;
        std::cout << "  - Assignments: " << assignments << std::endl;
        std::cout << "  - String literals: " << stringLiterals << std::endl;
        std::cout << "  - Control flow nodes: " << controlFlowNodes << std::endl;

        // Output handling
        bool outputSuccess = false;
        if (saveLocal) {
            saveGraphLocally(codeGraph);
            outputSuccess = true;
        } else {
            // Try to upload to API endpoint
            outputSuccess = uploadGraph(codeGraph, apiEndpoint);
            if (!outputSuccess) {
                std::cerr << "Upload failed, falling back to local save..." << std::endl;
                saveGraphLocally(codeGraph);
                outputSuccess = true;
            }
        }

        if (!outputSuccess) {
            std::cerr << "Failed to save code graph!" << std::endl;
            curl_global_cleanup();
            return 1;
        }
    } else {
        std::cerr << "Code analysis failed with error code: " << result << std::endl;
        curl_global_cleanup();
        return result;
    }

    curl_global_cleanup();
    return 0;
}