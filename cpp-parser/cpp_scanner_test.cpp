#include <clang/Tooling/CommonOptionsParser.h>
#include <clang/Tooling/Tooling.h>
#include <clang/ASTMatchers/ASTMatchers.h>
#include <clang/ASTMatchers/ASTMatchFinder.h>
#include <clang/Frontend/FrontendActions.h>
#include <clang/Frontend/CompilerInstance.h>
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/AST/Stmt.h>
#include <clang/AST/Expr.h>
#include <clang/AST/Type.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Support/CommandLine.h>
#include <fstream>
#include <unordered_map>
#include <map>
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

// Create a custom option category
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
std::vector<json> nodes;
std::vector<json> edges;
int nextId = 1;
std::unordered_map<const void*, int> nodeIds;
std::map<std::string, int> variableToNodeId;

// Statistics counters
int methodCalls = 0, assignments = 0, stringLiterals = 0, controlFlows = 0;

// Utility functions
std::string generateUUID() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 15);
    std::uniform_int_distribution<> dis2(8, 11);
    
    std::stringstream ss;
    ss << std::hex;
    for (int i = 0; i < 32; ++i) {
        if (i == 8 || i == 12 || i == 16 || i == 20) ss << "-";
        if (i == 12) ss << "4";
        else if (i == 16) ss << dis2(gen);
        else ss << dis(gen);
    }
    return ss.str();
}

int getNextId() {
    return nextId++;
}

json createEdge(int source, int target, const std::string& type) {
    json edge;
    edge["source"] = source;
    edge["target"] = target;
    edge["type"] = type;
    return edge;
}

void addEdge(int source, int target, const std::string& type) {
    edges.push_back(createEdge(source, target, type));
}

std::string getStmtString(const Stmt* stmt, ASTContext* context) {
    if (!stmt) return "";
    std::string result;
    llvm::raw_string_ostream stream(result);
    stmt->printPretty(stream, nullptr, context->getPrintingPolicy());
    return stream.str();
}

std::string getExprString(const Expr* expr, ASTContext* context) {
    if (!expr) return "";
    std::string result;
    llvm::raw_string_ostream stream(result);
    expr->printPretty(stream, nullptr, context->getPrintingPolicy());
    return stream.str();
}

class CodeGraphVisitor : public RecursiveASTVisitor<CodeGraphVisitor> {
public:
    explicit CodeGraphVisitor(ASTContext* Context) : Context(Context) {}

    bool VisitTranslationUnitDecl(TranslationUnitDecl* TU) {
        // Create file node for each source file
        SourceManager& SM = Context->getSourceManager();
        FileID MainFileID = SM.getMainFileID();
        const FileEntry* FE = SM.getFileEntryForID(MainFileID);
        
        if (FE) {
            json fileNode;
            fileNode["id"] = getNextId();
            fileNode["type"] = "FILE";
            fileNode["name"] = FE->getName().str();
            nodes.push_back(fileNode);
            nodeIds[TU] = fileNode["id"];
        }
        return true;
    }

    bool VisitCXXRecordDecl(CXXRecordDecl* Class) {
        if (!Class->isThisDeclarationADefinition()) return true;

        json classNode;
        int classId = getNextId();
        classNode["id"] = classId;
        classNode["type"] = Class->isClass() ? "CLASS" : (Class->isStruct() ? "STRUCT" : "INTERFACE");
        classNode["name"] = Class->getNameAsString();
        nodes.push_back(classNode);
        nodeIds[Class] = classId;

        // Link to parent (file or namespace)
        if (auto parent = Class->getParent()) {
            if (nodeIds.count(parent)) {
                addEdge(nodeIds[parent], classId, "CONTAINS");
            }
        }

        return true;
    }

    bool VisitCXXConstructorDecl(CXXConstructorDecl* Constructor) {
        json constructorNode;
        int constructorId = getNextId();
        constructorNode["id"] = constructorId;
        constructorNode["type"] = "CONSTRUCTOR";
        constructorNode["name"] = Constructor->getNameAsString();
        constructorNode["parameters"] = Constructor->getNumParams();
        nodes.push_back(constructorNode);
        nodeIds[Constructor] = constructorId;

        // Link to class
        if (auto parent = Constructor->getParent()) {
            if (nodeIds.count(parent)) {
                addEdge(nodeIds[parent], constructorId, "CONTAINS");
            }
        }

        // Process parameters
        for (const ParmVarDecl* Param : Constructor->parameters()) {
            processParameter(Param, constructorId);
        }

        // Process constructor body
        if (Constructor->hasBody()) {
            analyzeMethodBody(Constructor->getBody(), constructorId);
        }

        return true;
    }

    bool VisitCXXMethodDecl(CXXMethodDecl* Method) {
        json methodNode;
        int methodId = getNextId();
        methodNode["id"] = methodId;
        methodNode["type"] = "METHOD";
        methodNode["name"] = Method->getNameAsString();
        methodNode["returnType"] = Method->getReturnType().getAsString();
        methodNode["parameters"] = Method->getNumParams();
        nodes.push_back(methodNode);
        nodeIds[Method] = methodId;

        // Link to class
        if (auto parent = Method->getParent()) {
            if (nodeIds.count(parent)) {
                addEdge(nodeIds[parent], methodId, "CONTAINS");
            }
        }

        // Process parameters
        for (const ParmVarDecl* Param : Method->parameters()) {
            processParameter(Param, methodId);
        }

        // Process method body
        if (Method->hasBody()) {
            analyzeMethodBody(Method->getBody(), methodId);
        }

        return true;
    }

    bool VisitFunctionDecl(FunctionDecl* Function) {
        // Skip if it's a method (handled by VisitCXXMethodDecl)
        if (isa<CXXMethodDecl>(Function)) return true;

        json functionNode;
        int functionId = getNextId();
        functionNode["id"] = functionId;
        functionNode["type"] = "FUNCTION";
        functionNode["name"] = Function->getNameAsString();
        functionNode["returnType"] = Function->getReturnType().getAsString();
        functionNode["parameters"] = Function->getNumParams();
        nodes.push_back(functionNode);
        nodeIds[Function] = functionId;

        // Process parameters
        for (const ParmVarDecl* Param : Function->parameters()) {
            processParameter(Param, functionId);
        }

        // Process function body
        if (Function->hasBody()) {
            analyzeMethodBody(Function->getBody(), functionId);
        }

        return true;
    }

    bool VisitFieldDecl(FieldDecl* Field) {
        json fieldNode;
        int fieldId = getNextId();
        fieldNode["id"] = fieldId;
        fieldNode["type"] = "FIELD";
        fieldNode["name"] = Field->getNameAsString();
        fieldNode["dataType"] = Field->getType().getAsString();
        nodes.push_back(fieldNode);
        nodeIds[Field] = fieldId;

        // Link to class
        if (auto parent = Field->getParent()) {
            if (nodeIds.count(parent)) {
                addEdge(nodeIds[parent], fieldId, "DECLARES");
            }
        }

        return true;
    }

private:
    ASTContext* Context;

    void processParameter(const ParmVarDecl* Param, int parentId) {
        json paramNode;
        int paramId = getNextId();
        paramNode["id"] = paramId;
        paramNode["type"] = "PARAMETER";
        paramNode["name"] = Param->getNameAsString();
        paramNode["dataType"] = Param->getType().getAsString();
        nodes.push_back(paramNode);
        nodeIds[Param] = paramId;
        
        addEdge(parentId, paramId, "DECLARES");
        variableToNodeId[Param->getNameAsString()] = paramId;
    }

    void analyzeMethodBody(const Stmt* Body, int methodId) {
        if (!Body) return;

        // Process variable declarations
        for (auto it = Body->child_begin(); it != Body->child_end(); ++it) {
            processStmtRecursively(*it, methodId);
        }
    }

    void processStmtRecursively(const Stmt* S, int parentId) {
        if (!S) return;

        // Variable declarations
        if (const DeclStmt* DS = dyn_cast<DeclStmt>(S)) {
            for (const Decl* D : DS->decls()) {
                if (const VarDecl* VD = dyn_cast<VarDecl>(D)) {
                    processLocalVariable(VD, parentId);
                }
            }
        }
        
        // Method calls
        else if (const CallExpr* CE = dyn_cast<CallExpr>(S)) {
            processMethodCall(CE, parentId);
        }
        
        // Object creation (CXXConstructExpr)
        else if (const CXXConstructExpr* CCE = dyn_cast<CXXConstructExpr>(S)) {
            processObjectCreation(CCE, parentId);
        }
        
        // New expressions
        else if (const CXXNewExpr* NE = dyn_cast<CXXNewExpr>(S)) {
            processNewExpression(NE, parentId);
        }
        
        // Array subscript
        else if (const ArraySubscriptExpr* ASE = dyn_cast<ArraySubscriptExpr>(S)) {
            processArrayAccess(ASE, parentId);
        }
        
        // Try-catch blocks
        else if (const CXXTryStmt* TS = dyn_cast<CXXTryStmt>(S)) {
            processTryStatement(TS, parentId);
        }
        
        // Return statements
        else if (const ReturnStmt* RS = dyn_cast<ReturnStmt>(S)) {
            processReturnStatement(RS, parentId);
        }
        
        // Binary expressions
        else if (const BinaryOperator* BO = dyn_cast<BinaryOperator>(S)) {
            processBinaryExpression(BO, parentId);
            if (BO->isAssignmentOp()) {
                processAssignment(BO, parentId);
            }
        }
        
        // Field access
        else if (const MemberExpr* ME = dyn_cast<MemberExpr>(S)) {
            processFieldAccess(ME, parentId);
        }
        
        // String literals - FIXED: Added safety check
        else if (const StringLiteral* SL = dyn_cast<StringLiteral>(S)) {
            processStringLiteral(SL, parentId);
        }
        
        // Control flow
        else if (const IfStmt* IS = dyn_cast<IfStmt>(S)) {
            processIfStatement(IS, parentId);
        }
        else if (const ForStmt* FS = dyn_cast<ForStmt>(S)) {
            processForStatement(FS, parentId);
        }
        else if (const WhileStmt* WS = dyn_cast<WhileStmt>(S)) {
            processWhileStatement(WS, parentId);
        }
        else if (const CXXForRangeStmt* FRS = dyn_cast<CXXForRangeStmt>(S)) {
            processForEachStatement(FRS, parentId);
        }

        // Recursively process children
        for (auto it = S->child_begin(); it != S->child_end(); ++it) {
            processStmtRecursively(*it, parentId);
        }
    }

    void processLocalVariable(const VarDecl* VD, int methodId) {
        json varNode;
        int varId = getNextId();
        varNode["id"] = varId;
        varNode["type"] = "LOCAL_VARIABLE";
        varNode["name"] = VD->getNameAsString();
        varNode["dataType"] = VD->getType().getAsString();
        
        if (VD->hasInit()) {
            varNode["initializer"] = getExprString(VD->getInit(), Context);
        }
        
        nodes.push_back(varNode);
        nodeIds[VD] = varId;
        variableToNodeId[VD->getNameAsString()] = varId;
        
        addEdge(methodId, varId, "DECLARES");
    }

    void processMethodCall(const CallExpr* CE, int methodId) {
        json callNode;
        int callId = getNextId();
        callNode["id"] = callId;
        callNode["type"] = "METHOD_CALL";
        
        if (const FunctionDecl* FD = CE->getDirectCallee()) {
            callNode["name"] = FD->getNameAsString();
        } else {
            callNode["name"] = getExprString(CE->getCallee(), Context);
        }
        
        callNode["arguments"] = CE->getNumArgs();
        
        if (const Expr* callee = CE->getCallee()) {
            if (const MemberExpr* ME = dyn_cast<MemberExpr>(callee)) {
                callNode["scope"] = getExprString(ME->getBase(), Context);
            }
        }
        
        nodes.push_back(callNode);
        nodeIds[CE] = callId;
        methodCalls++;
        
        addEdge(methodId, callId, "INVOKES");
        
        // Process arguments for data flow
        for (const Expr* Arg : CE->arguments()) {
            processArgument(Arg, callId);
        }
    }

    void processObjectCreation(const CXXConstructExpr* CCE, int methodId) {
        json objNode;
        int objId = getNextId();
        objNode["id"] = objId;
        objNode["type"] = "OBJECT_CREATION";
        objNode["className"] = CCE->getType().getAsString();
        objNode["arguments"] = CCE->getNumArgs();
        
        nodes.push_back(objNode);
        nodeIds[CCE] = objId;
        methodCalls++;
        
        addEdge(methodId, objId, "INVOKES");
        
        // Process arguments
        for (const Expr* Arg : CCE->arguments()) {
            processArgument(Arg, objId);
        }
    }

    void processNewExpression(const CXXNewExpr* NE, int methodId) {
        json newNode;
        int newId = getNextId();
        newNode["id"] = newId;
        newNode["type"] = "OBJECT_CREATION";
        newNode["className"] = NE->getAllocatedType().getAsString();
        
        // Count arguments: placement args + constructor args
        unsigned numArgs = NE->getNumPlacementArgs();
        if (const CXXConstructExpr* CE = NE->getConstructExpr()) {
            numArgs += CE->getNumArgs();
        }
        newNode["arguments"] = numArgs;
        
        nodes.push_back(newNode);
        nodeIds[NE] = newId;
        methodCalls++;
        
        addEdge(methodId, newId, "INVOKES");
    }

    void processArrayAccess(const ArraySubscriptExpr* ASE, int methodId) {
        json arrayNode;
        int arrayId = getNextId();
        arrayNode["id"] = arrayId;
        arrayNode["type"] = "TYPE_ARRAY_CALL";
        arrayNode["array"] = getExprString(ASE->getBase(), Context);
        arrayNode["index"] = getExprString(ASE->getIdx(), Context);
        
        nodes.push_back(arrayNode);
        nodeIds[ASE] = arrayId;
        methodCalls++;
        
        addEdge(methodId, arrayId, "INVOKES");
    }

    void processTryStatement(const CXXTryStmt* TS, int methodId) {
        json tryNode;
        int tryId = getNextId();
        tryNode["id"] = tryId;
        tryNode["type"] = "TRY_CATCH_BLOCK";
        tryNode["catchClausesCount"] = TS->getNumHandlers();
        tryNode["hasFinallyBlock"] = false; // C++ doesn't have finally
        
        json exceptionTypes = json::array();
        for (unsigned i = 0; i < TS->getNumHandlers(); ++i) {
            const CXXCatchStmt* CS = TS->getHandler(i);
            if (const VarDecl* ExceptionDecl = CS->getExceptionDecl()) {
                json paramNode;
                int paramId = getNextId();
                paramNode["id"] = paramId;
                paramNode["type"] = "TYPE_CATCH_CALL";
                paramNode["name"] = ExceptionDecl->getNameAsString();
                paramNode["dataType"] = ExceptionDecl->getType().getAsString();
                
                nodes.push_back(paramNode);
                nodeIds[ExceptionDecl] = paramId;
                variableToNodeId[ExceptionDecl->getNameAsString()] = paramId;
                
                addEdge(tryId, paramId, "DECLARES");
                exceptionTypes.push_back(ExceptionDecl->getType().getAsString());
            }
        }
        tryNode["exceptionTypes"] = exceptionTypes;
        
        nodes.push_back(tryNode);
        nodeIds[TS] = tryId;
        controlFlows++;
        
        addEdge(methodId, tryId, "CONTAINS_EXCEPTION_HANDLING");
    }

    void processReturnStatement(const ReturnStmt* RS, int methodId) {
        json returnNode;
        int returnId = getNextId();
        returnNode["id"] = returnId;
        returnNode["type"] = "RETURN_STATEMENT";
        
        if (const Expr* RetValue = RS->getRetValue()) {
            returnNode["expression"] = getExprString(RetValue, Context);
        }
        
        nodes.push_back(returnNode);
        nodeIds[RS] = returnId;
        
        addEdge(methodId, returnId, "CONTAINS");
    }

    void processBinaryExpression(const BinaryOperator* BO, int parentId) {
        json exprNode;
        int exprId = getNextId();
        exprNode["id"] = exprId;
        exprNode["type"] = "BINARY_EXPRESSION";
        exprNode["operator"] = BO->getOpcodeStr().str();
        exprNode["leftOperand"] = getExprString(BO->getLHS(), Context);
        exprNode["rightOperand"] = getExprString(BO->getRHS(), Context);
        
        nodes.push_back(exprNode);
        nodeIds[BO] = exprId;
        
        addEdge(parentId, exprId, "CONTAINS_EXPRESSION");
    }

    void processAssignment(const BinaryOperator* BO, int methodId) {
        json assignNode;
        int assignId = getNextId();
        assignNode["id"] = assignId;
        assignNode["type"] = "ASSIGNMENT";
        assignNode["target"] = getExprString(BO->getLHS(), Context);
        assignNode["value"] = getExprString(BO->getRHS(), Context);
        assignNode["operator"] = BO->getOpcodeStr().str();
        
        nodes.push_back(assignNode);
        nodeIds[BO] = assignId;
        assignments++;
        
        addEdge(assignId, methodId, "CONTAINS_ASSIGNMENT");
    }

    void processFieldAccess(const MemberExpr* ME, int methodId) {
        json fieldAccessNode;
        int fieldAccessId = getNextId();
        fieldAccessNode["id"] = fieldAccessId;
        fieldAccessNode["type"] = "FIELD_ACCESS";
        fieldAccessNode["field"] = ME->getMemberNameInfo().getAsString();
        fieldAccessNode["scope"] = getExprString(ME->getBase(), Context);
        
        nodes.push_back(fieldAccessNode);
        nodeIds[ME] = fieldAccessId;
        
        addEdge(methodId, fieldAccessId, "ACCESSES");
    }

    void processStringLiteral(const StringLiteral* SL, int methodId) {
        json stringNode;
        int stringId = getNextId();
        stringNode["id"] = stringId;
        stringNode["type"] = "STRING_LITERAL";
        
        // FIXED: Add safety checks for string literals
        try {
            // Check if it's a regular char string literal
            if (SL->getCharByteWidth() == 1) {
                stringNode["value"] = SL->getString().str();
            } else {
                // Handle wide/UTF strings more safely
                stringNode["value"] = "<wide_string>";
                stringNode["encoding"] = "wide";
            }
            stringNode["length"] = SL->getLength();
        } catch (...) {
            // Fallback for problematic string literals
            stringNode["value"] = "<string_literal>";
            stringNode["length"] = 0;
        }
        
        nodes.push_back(stringNode);
        nodeIds[SL] = stringId;
        stringLiterals++;
        
        addEdge(methodId, stringId, "CONTAINS_LITERAL");
    }

    void processIfStatement(const IfStmt* IS, int methodId) {
        json ifNode;
        int ifId = getNextId();
        ifNode["id"] = ifId;
        ifNode["type"] = "IF_STATEMENT";
        ifNode["condition"] = getExprString(IS->getCond(), Context);
        ifNode["hasElse"] = (IS->getElse() != nullptr);
        
        nodes.push_back(ifNode);
        nodeIds[IS] = ifId;
        controlFlows++;
        
        addEdge(methodId, ifId, "CONTAINS_CONTROL_FLOW");
    }

    void processForStatement(const ForStmt* FS, int methodId) {
        json forNode;
        int forId = getNextId();
        forNode["id"] = forId;
        forNode["type"] = "FOR_LOOP";
        
        if (const Expr* Cond = FS->getCond()) {
            forNode["condition"] = getExprString(Cond, Context);
        }
        
        nodes.push_back(forNode);
        nodeIds[FS] = forId;
        controlFlows++;
        
        addEdge(methodId, forId, "CONTAINS_CONTROL_FLOW");
    }

    void processWhileStatement(const WhileStmt* WS, int methodId) {
        json whileNode;
        int whileId = getNextId();
        whileNode["id"] = whileId;
        whileNode["type"] = "WHILE_LOOP";
        whileNode["condition"] = getExprString(WS->getCond(), Context);
        
        nodes.push_back(whileNode);
        nodeIds[WS] = whileId;
        controlFlows++;
        
        addEdge(methodId, whileId, "CONTAINS_CONTROL_FLOW");
    }

    void processForEachStatement(const CXXForRangeStmt* FRS, int methodId) {
        json forEachNode;
        int forEachId = getNextId();
        forEachNode["id"] = forEachId;
        forEachNode["type"] = "FOR_EACH_LOOP";
        forEachNode["variable"] = getStmtString(FRS->getLoopVarStmt(), Context);
        forEachNode["iterable"] = getExprString(FRS->getRangeInit(), Context);
        
        nodes.push_back(forEachNode);
        nodeIds[FRS] = forEachId;
        controlFlows++;
        
        addEdge(methodId, forEachId, "CONTAINS_CONTROL_FLOW");
    }

    void processArgument(const Expr* Arg, int targetNodeId) {
        // Process data flow from arguments
        if (const DeclRefExpr* DRE = dyn_cast<DeclRefExpr>(Arg)) {
            std::string varName = DRE->getNameInfo().getAsString();
            if (variableToNodeId.count(varName)) {
                addEdge(variableToNodeId[varName], targetNodeId, "DATA_FLOW");
            }
        }
        // Handle nested expressions recursively
        for (auto it = Arg->child_begin(); it != Arg->child_end(); ++it) {
            if (const Expr* ChildExpr = dyn_cast<Expr>(*it)) {
                processArgument(ChildExpr, targetNodeId);
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

// HTTP upload functionality
size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* response) {
    size_t totalSize = size * nmemb;
    response->append((char*)contents, totalSize);
    return totalSize;
}

void uploadGraph(const json& codeGraph) {
    CURL* curl = curl_easy_init();
    if (!curl) {
        throw std::runtime_error("Failed to initialize CURL");
    }

    std::string jsonStr = codeGraph.dump();
    std::string response;
    
    curl_easy_setopt(curl, CURLOPT_URL, apiEndpoint.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonStr.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, jsonStr.length());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    
    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "Authorization: Basic dXNlcjpzZWNyZXQ="); // user:secret
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    
    CURLcode res = curl_easy_perform(curl);
    long responseCode;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &responseCode);
    
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    
    if (res != CURLE_OK || responseCode != 200) {
        throw std::runtime_error("Failed to upload code graph: HTTP error code " + std::to_string(responseCode));
    }
    
    std::cout << "Code graph uploaded successfully to: " << apiEndpoint 
              << " with scanId: " << codeGraph["scanId"].get<std::string>() << std::endl;
}

void saveGraphLocally(const json& codeGraph) {
    std::filesystem::path outputFile(outputPath);
    
    // Only create directories if the path has a parent directory
    if (outputFile.has_parent_path() && !outputFile.parent_path().empty()) {
        try {
            std::filesystem::create_directories(outputFile.parent_path());
        } catch (const std::filesystem::filesystem_error& e) {
            std::cerr << "Warning: Could not create directories: " << e.what() << std::endl;
            // Continue anyway, maybe the file can be created in current directory
        }
    }
    
    std::ofstream file(outputFile);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open output file: " + outputPath);
    }
    
    file << codeGraph.dump(2);
    std::cout << "Code graph saved to: " << std::filesystem::absolute(outputFile) << std::endl;
}

/*
void parseArguments(int argc, const char** argv) {
    for (int i = 0; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--local") {
            saveLocal = true;
        } else if (arg == "--output" && i + 1 < argc) {
            outputPath = argv[++i];
        } else if (arg == "--endpoint" && i + 1 < argc) {
            apiEndpoint = argv[++i];
        }
    }
}
*/
int main(int argc, const char** argv) {
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <source-files> [-local] [-output=path.json] [-endpoint=url] -- [clang-options]" << std::endl;
        return 1;
    }

    llvm::cl::OptionCategory ToolCategory("cpp-scanner");
    auto ExpectedParser = CommonOptionsParser::create(argc, argv, ToolCategory);
    if (!ExpectedParser) {
        llvm::errs() << ExpectedParser.takeError();
        return 1;
    }
    CommonOptionsParser& OptionsParser = ExpectedParser.get();
    ClangTool Tool(OptionsParser.getCompilations(), OptionsParser.getSourcePathList());

    // Set global variables from command line options
    saveLocal = SaveLocal;
    if (!OutputPath.empty()) {
        outputPath = OutputPath;
    }
    if (!ApiEndpoint.empty()) {
        apiEndpoint = ApiEndpoint;
    }

    // Initialize code graph
    codeGraph = json::object();
    codeGraph["scanId"] = generateUUID();
    codeGraph["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    codeGraph["version"] = "1.0";
    codeGraph["language"] = "C++";
    
    // Initialize global containers
    nodes.clear();
    edges.clear();
    nextId = 1;
    nodeIds.clear();
    variableToNodeId.clear();
    
    // Reset statistics
    methodCalls = 0;
    assignments = 0;
    stringLiterals = 0;
    controlFlows = 0;

    // Run the tool
    std::cout << "Starting C++ code analysis..." << std::endl;
    int result = Tool.run(newFrontendActionFactory<CodeGraphAction>().get());
    
    if (result != 0) {
        std::cerr << "Error: Analysis failed with code " << result << std::endl;
        return result;
    }

    // Finalize the code graph
    codeGraph["nodes"] = nodes;
    codeGraph["edges"] = edges;
    codeGraph["statistics"] = json::object();
    codeGraph["statistics"]["totalNodes"] = nodes.size();
    codeGraph["statistics"]["totalEdges"] = edges.size();
    codeGraph["statistics"]["methodCalls"] = methodCalls;
    codeGraph["statistics"]["assignments"] = assignments;
    codeGraph["statistics"]["stringLiterals"] = stringLiterals;
    codeGraph["statistics"]["controlFlows"] = controlFlows;

    // Print analysis summary
    std::cout << "Analysis completed!" << std::endl;
    std::cout << "Generated " << nodes.size() << " nodes and " << edges.size() << " edges" << std::endl;
    std::cout << "Statistics:" << std::endl;
    std::cout << "  Method calls: " << methodCalls << std::endl;
    std::cout << "  Assignments: " << assignments << std::endl;
    std::cout << "  String literals: " << stringLiterals << std::endl;
    std::cout << "  Control flows: " << controlFlows << std::endl;

    try {
        if (saveLocal) {
            saveGraphLocally(codeGraph);
        } else {
            uploadGraph(codeGraph);
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        
        // Fallback: try to save locally if upload fails
        if (!saveLocal) {
            std::cout << "Attempting to save locally as fallback..." << std::endl;
            try {
                // Use default filename for fallback
                std::string originalPath = outputPath;
                outputPath = "../../output/codegraph_cpp.json";
                saveGraphLocally(codeGraph);
                outputPath = originalPath; // restore
            } catch (const std::exception& fallbackE) {
                std::cerr << "Fallback save also failed: " << fallbackE.what() << std::endl;
                return 1;
            }
        } else {
            return 1;
        }
    }

    return 0;
}