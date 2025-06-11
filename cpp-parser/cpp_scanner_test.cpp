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
#include <unordered_set>
#include <map>
#include <set>
#include <vector>
#include <string>
#include <sstream>
#include <iostream>
#include <filesystem>
#include <random>
#include <chrono>
#include <curl/curl.h>
#include <json.hpp>
#include <regex>

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
std::map<std::string, std::set<int>> scopedVariables; // scope -> variable node IDs

// Enhanced statistics counters
int methodCalls = 0, assignments = 0, stringLiterals = 0, controlFlows = 0;
int objectCreations = 0, taintSources = 0, taintSinks = 0, dataFlows = 0;

// Taint analysis data structures
std::unordered_set<std::string> taintSourceFunctions = {
    // Input functions
    "scanf", "fscanf", "sscanf", "gets", "fgets", "getline", "cin",
    "read", "recv", "recvfrom", "getenv", "getchar", "fgetc",
    // Network input
    "accept", "recvmsg", "WSARecv", "WSARecvFrom",
    // File input
    "fread", "readdir", "getpwnam", "getgrnam"
};

std::unordered_set<std::string> taintSinkFunctions = {
    // Command execution
    "system", "execl", "execlp", "execle", "execv", "execvp", "execve",
    "popen", "ShellExecute", "CreateProcess", "WinExec",
    // File operations
    "fopen", "open", "creat", "unlink", "remove", "rename",
    // Network operations
    "send", "sendto", "sendmsg", "connect", "bind",
    // Memory operations
    "strcpy", "strcat", "sprintf", "vsprintf", "memcpy", "memmove",
    // SQL (common C++ database libraries)
    "mysql_query", "sqlite3_exec", "PQexec", "SQLExecDirect"
};

std::unordered_set<std::string> dangerousFunctions = {
    "gets", "strcpy", "strcat", "sprintf", "vsprintf", "scanf"
};

// Data flow tracking
struct TaintInfo {
    int nodeId;
    std::string source;
    std::vector<std::string> propagationPath;
    bool isTainted = false;
};

std::map<std::string, TaintInfo> taintedVariables;

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

json createEdge(int source, int target, const std::string& type, const std::string& label = "") {
    json edge;
    edge["source"] = source;
    edge["target"] = target;
    edge["type"] = type;
    if (!label.empty()) {
        edge["label"] = label;
    }
    return edge;
}

void addEdge(int source, int target, const std::string& type, const std::string& label = "") {
    edges.push_back(createEdge(source, target, type, label));
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

// Safe string literal extraction function
std::string getStringLiteralValue(const StringLiteral* SL) {
    if (!SL) return "";
    
    try {
        // Check the character width to handle different string types safely
        if (SL->getCharByteWidth() == 1) {
            // Regular char string
            return SL->getString().str();
        } else if (SL->getCharByteWidth() == 2) {
            // UTF-16 string (char16_t)
            return "UTF16_STRING";
        } else if (SL->getCharByteWidth() == 4) {
            // UTF-32 string (char32_t)
            return "UTF32_STRING";
        } else {
            // Wide string (wchar_t) or other
            return "WIDE_STRING";
        }
    } catch (...) {
        // Fallback for any issues
        return "STRING_LITERAL";
    }
}

std::string getCurrentScope(const DeclContext* DC) {
    std::string scope;
    while (DC && !isa<TranslationUnitDecl>(DC)) {
        if (const NamedDecl* ND = dyn_cast<NamedDecl>(DC)) {
            if (!scope.empty()) scope = "::" + scope;
            scope = ND->getNameAsString() + scope;
        }
        DC = DC->getParent();
    }
    return scope.empty() ? "global" : scope;
}

bool isTaintSource(const std::string& functionName) {
    return taintSourceFunctions.count(functionName) > 0;
}

bool isTaintSink(const std::string& functionName) {
    return taintSinkFunctions.count(functionName) > 0;
}

bool isDangerousFunction(const std::string& functionName) {
    return dangerousFunctions.count(functionName) > 0;
}

class EnhancedCodeGraphVisitor : public RecursiveASTVisitor<EnhancedCodeGraphVisitor> {
public:
    explicit EnhancedCodeGraphVisitor(ASTContext* Context) : Context(Context) {}

    bool VisitTranslationUnitDecl(TranslationUnitDecl* TU) {
        // Create file node for each source file
        SourceManager& SM = Context->getSourceManager();
        FileID MainFileID = SM.getMainFileID();
        
        if (auto FE = SM.getFileEntryRefForID(MainFileID)) {
            json fileNode;
            fileNode["id"] = getNextId();
            fileNode["type"] = "FILE";
            fileNode["name"] = FE->getName().str();
            fileNode["path"] = FE->getName().str();
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
        classNode["qualifiedName"] = Class->getQualifiedNameAsString();
        classNode["isAbstract"] = Class->isAbstract();
        
        // Track inheritance
        if (Class->getNumBases() > 0) {
            json baseClasses = json::array();
            for (const auto& Base : Class->bases()) {
                baseClasses.push_back(Base.getType().getAsString());
            }
            classNode["baseClasses"] = baseClasses;
        }

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
        constructorNode["isPublic"] = Constructor->getAccess() == AS_public;
        constructorNode["isDefault"] = Constructor->isDefaultConstructor();
        constructorNode["isCopy"] = Constructor->isCopyConstructor();
        constructorNode["isMove"] = Constructor->isMoveConstructor();
        
        nodes.push_back(constructorNode);
        nodeIds[Constructor] = constructorId;

        // Link to class
        if (auto parent = Constructor->getParent()) {
            if (nodeIds.count(parent)) {
                addEdge(nodeIds[parent], constructorId, "DECLARES");
            }
        }

        // Process parameters
        for (const ParmVarDecl* Param : Constructor->parameters()) {
            processParameter(Param, constructorId);
        }

        // Process constructor body
        if (Constructor->hasBody()) {
            analyzeMethodBody(Constructor->getBody(), constructorId, Constructor->getNameAsString());
        }

        return true;
    }

    bool VisitCXXMethodDecl(CXXMethodDecl* Method) {
        json methodNode;
        int methodId = getNextId();
        methodNode["id"] = methodId;
        methodNode["type"] = "METHOD";
        methodNode["name"] = Method->getNameAsString();
        methodNode["qualifiedName"] = Method->getQualifiedNameAsString();
        methodNode["returnType"] = Method->getReturnType().getAsString();
        methodNode["parameters"] = Method->getNumParams();
        methodNode["isPublic"] = Method->getAccess() == AS_public;
        methodNode["isStatic"] = Method->isStatic();
        methodNode["isVirtual"] = Method->isVirtual();
        methodNode["isConst"] = Method->isConst();
        
        nodes.push_back(methodNode);
        nodeIds[Method] = methodId;

        // Link to class
        if (auto parent = Method->getParent()) {
            if (nodeIds.count(parent)) {
                addEdge(nodeIds[parent], methodId, "DECLARES");
            }
        }

        // Process parameters
        for (const ParmVarDecl* Param : Method->parameters()) {
            processParameter(Param, methodId);
        }

        // Process method body
        if (Method->hasBody()) {
            analyzeMethodBody(Method->getBody(), methodId, Method->getNameAsString());
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
        functionNode["qualifiedName"] = Function->getQualifiedNameAsString();
        functionNode["returnType"] = Function->getReturnType().getAsString();
        functionNode["parameters"] = Function->getNumParams();
        functionNode["isStatic"] = Function->getStorageClass() == SC_Static;
        functionNode["isInline"] = Function->isInlineSpecified();
        
        nodes.push_back(functionNode);
        nodeIds[Function] = functionId;

        // Process parameters (including main function argv)
        for (const ParmVarDecl* Param : Function->parameters()) {
            processParameter(Param, functionId);
            
            // Special handling for main function parameters (potential taint sources)
            if (Function->getNameAsString() == "main") {
                if (Param->getNameAsString() == "argv" || 
                    Param->getType().getAsString().find("char") != std::string::npos) {
                    markVariableAsTainted(Param->getNameAsString(), functionId, "command_line_args");
                }
            }
        }

        // Process function body
        if (Function->hasBody()) {
            analyzeMethodBody(Function->getBody(), functionId, Function->getNameAsString());
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
        fieldNode["isPublic"] = Field->getAccess() == AS_public;
        fieldNode["isMutable"] = Field->isMutable();
        
        if (Field->hasInClassInitializer()) {
            fieldNode["hasInitializer"] = true;
            fieldNode["initializer"] = getExprString(Field->getInClassInitializer(), Context);
        }
        
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
        
        if (Param->hasDefaultArg()) {
            paramNode["hasDefaultValue"] = true;
            paramNode["defaultValue"] = getExprString(Param->getDefaultArg(), Context);
        }
        
        nodes.push_back(paramNode);
        nodeIds[Param] = paramId;
        
        addEdge(parentId, paramId, "DECLARES");
        variableToNodeId[Param->getNameAsString()] = paramId;
    }

    void analyzeMethodBody(const Stmt* Body, int methodId, const std::string& methodName) {
        if (!Body) return;

        // Clear method-local variable scope
        std::string currentScope = methodName;
        scopedVariables[currentScope].clear();

        // Process all statements recursively
        processStmtRecursively(Body, methodId, currentScope);
    }

    void processStmtRecursively(const Stmt* S, int parentId, const std::string& currentScope) {
        if (!S) return;

        // Variable declarations
        if (const DeclStmt* DS = dyn_cast<DeclStmt>(S)) {
            for (const Decl* D : DS->decls()) {
                if (const VarDecl* VD = dyn_cast<VarDecl>(D)) {
                    processLocalVariable(VD, parentId, currentScope);
                }
            }
        }
        
        // Method calls
        else if (const CallExpr* CE = dyn_cast<CallExpr>(S)) {
            processMethodCall(CE, parentId, currentScope);
        }
        
        // Object creation (CXXConstructExpr)
        else if (const CXXConstructExpr* CCE = dyn_cast<CXXConstructExpr>(S)) {
            processObjectCreation(CCE, parentId, currentScope);
        }
        
        // New expressions
        else if (const CXXNewExpr* NE = dyn_cast<CXXNewExpr>(S)) {
            processNewExpression(NE, parentId, currentScope);
        }
        
        // Array subscript
        else if (const ArraySubscriptExpr* ASE = dyn_cast<ArraySubscriptExpr>(S)) {
            processArrayAccess(ASE, parentId, currentScope);
        }
        
        // Try-catch blocks
        else if (const CXXTryStmt* TS = dyn_cast<CXXTryStmt>(S)) {
            processTryStatement(TS, parentId, currentScope);
        }
        
        // Return statements
        else if (const ReturnStmt* RS = dyn_cast<ReturnStmt>(S)) {
            processReturnStatement(RS, parentId, currentScope);
        }
        
        // Binary expressions (including assignments)
        else if (const BinaryOperator* BO = dyn_cast<BinaryOperator>(S)) {
            processBinaryExpression(BO, parentId, currentScope);
        }
        
        // Unary expressions
        else if (const UnaryOperator* UO = dyn_cast<UnaryOperator>(S)) {
            processUnaryExpression(UO, parentId, currentScope);
        }
        
        // Field access
        else if (const MemberExpr* ME = dyn_cast<MemberExpr>(S)) {
            processFieldAccess(ME, parentId, currentScope);
        }
        
        // String literals - FIXED to handle all string types safely
        else if (const StringLiteral* SL = dyn_cast<StringLiteral>(S)) {
            processStringLiteral(SL, parentId, currentScope);
        }
        
        // Numeric literals
        else if (const IntegerLiteral* IL = dyn_cast<IntegerLiteral>(S)) {
            processNumericLiteral(IL, parentId, "INTEGER");
        }
        else if (const FloatingLiteral* FL = dyn_cast<FloatingLiteral>(S)) {
            processNumericLiteral(FL, parentId, "FLOAT");
        }
        
        // Control flow
        else if (const IfStmt* IS = dyn_cast<IfStmt>(S)) {
            processIfStatement(IS, parentId, currentScope);
        }
        else if (const ForStmt* FS = dyn_cast<ForStmt>(S)) {
            processForStatement(FS, parentId, currentScope);
        }
        else if (const WhileStmt* WS = dyn_cast<WhileStmt>(S)) {
            processWhileStatement(WS, parentId, currentScope);
        }
        else if (const DoStmt* DS = dyn_cast<DoStmt>(S)) {
            processDoWhileStatement(DS, parentId, currentScope);
        }
        else if (const CXXForRangeStmt* FRS = dyn_cast<CXXForRangeStmt>(S)) {
            processForEachStatement(FRS, parentId, currentScope);
        }
        else if (const SwitchStmt* SS = dyn_cast<SwitchStmt>(S)) {
            processSwitchStatement(SS, parentId, currentScope);
        }

        // Recursively process children
        for (auto it = S->child_begin(); it != S->child_end(); ++it) {
            processStmtRecursively(*it, parentId, currentScope);
        }
    }

    void processLocalVariable(const VarDecl* VD, int methodId, const std::string& currentScope) {
        json varNode;
        int varId = getNextId();
        varNode["id"] = varId;
        varNode["type"] = "LOCAL_VARIABLE";
        varNode["name"] = VD->getNameAsString();
        varNode["dataType"] = VD->getType().getAsString();
        varNode["scope"] = currentScope;
        
        if (VD->hasInit()) {
            varNode["hasInitializer"] = true;
            varNode["initializer"] = getExprString(VD->getInit(), Context);
            
            // Create INITIALIZES edge
            json initNode;
            int initId = getNextId();
            initNode["id"] = initId;
            initNode["type"] = "INITIALIZER";
            initNode["expression"] = getExprString(VD->getInit(), Context);
            nodes.push_back(initNode);
            
            addEdge(varId, initId, "INITIALIZES");
            
            // Check for taint propagation in initializer
            checkTaintPropagation(VD->getInit(), VD->getNameAsString(), varId, currentScope);
        }
        
        nodes.push_back(varNode);
        nodeIds[VD] = varId;
        variableToNodeId[VD->getNameAsString()] = varId;
        scopedVariables[currentScope].insert(varId);
        
        addEdge(methodId, varId, "DECLARES");
    }

    void processMethodCall(const CallExpr* CE, int methodId, const std::string& currentScope) {
        json callNode;
        int callId = getNextId();
        callNode["id"] = callId;
        callNode["type"] = "METHOD_CALL";
        
        std::string functionName;
        if (const FunctionDecl* FD = CE->getDirectCallee()) {
            functionName = FD->getNameAsString();
            callNode["name"] = functionName;
            callNode["qualifiedName"] = FD->getQualifiedNameAsString();
        } else {
            functionName = getExprString(CE->getCallee(), Context);
            callNode["name"] = functionName;
        }
        
        callNode["arguments"] = CE->getNumArgs();
        
        // Determine scope/receiver
        if (const Expr* callee = CE->getCallee()) {
            if (const MemberExpr* ME = dyn_cast<MemberExpr>(callee)) {
                callNode["scope"] = getExprString(ME->getBase(), Context);
                callNode["isMethodCall"] = true;
            } else {
                callNode["isMethodCall"] = false;
            }
        }
        
        // Security analysis
        bool isTaintSourceCall = isTaintSource(functionName);
        bool isTaintSinkCall = isTaintSink(functionName);
        bool isDangerousCall = isDangerousFunction(functionName);
        
        callNode["isTaintSource"] = isTaintSourceCall;
        callNode["isTaintSink"] = isTaintSinkCall;
        callNode["isDangerous"] = isDangerousCall;
        
        if (isTaintSourceCall) {
            callNode["vulnerability"] = "TAINT_SOURCE";
            taintSources++;
        }
        if (isTaintSinkCall) {
            callNode["vulnerability"] = "TAINT_SINK";
            taintSinks++;
        }
        if (isDangerousCall) {
            callNode["vulnerability"] = "DANGEROUS_FUNCTION";
        }
        
        nodes.push_back(callNode);
        nodeIds[CE] = callId;
        methodCalls++;
        
        addEdge(methodId, callId, "INVOKES");
        
        // Process arguments for data flow and taint analysis
        for (unsigned i = 0; i < CE->getNumArgs(); ++i) {
            const Expr* Arg = CE->getArg(i);
            processArgument(Arg, callId, i, currentScope);
            
            // Check if tainted data flows to sink
            if (isTaintSinkCall) {
                checkTaintedArgumentToSink(Arg, callId, functionName, i);
            }
        }
        
        // Special handling for taint sources
        if (isTaintSourceCall) {
            // Mark return value as tainted (if assigned to a variable)
            // This would be handled in assignment processing
        }
    }

    void processObjectCreation(const CXXConstructExpr* CCE, int methodId, const std::string& currentScope) {
        json objNode;
        int objId = getNextId();
        objNode["id"] = objId;
        objNode["type"] = "OBJECT_CREATION";
        objNode["className"] = CCE->getType().getAsString();
        objNode["arguments"] = CCE->getNumArgs();
        objNode["isDirectInit"] = CCE->isListInitialization();
        
        if (const CXXConstructorDecl* Ctor = CCE->getConstructor()) {
            objNode["constructorName"] = Ctor->getNameAsString();
        }
        
        nodes.push_back(objNode);
        nodeIds[CCE] = objId;
        objectCreations++;
        
        addEdge(methodId, objId, "CREATES");
        
        // Process arguments
        for (unsigned i = 0; i < CCE->getNumArgs(); ++i) {
            const Expr* Arg = CCE->getArg(i);
            processArgument(Arg, objId, i, currentScope);
        }
    }

    void processNewExpression(const CXXNewExpr* NE, int methodId, const std::string& currentScope) {
        json newNode;
        int newId = getNextId();
        newNode["id"] = newId;
        newNode["type"] = "OBJECT_CREATION";
        newNode["className"] = NE->getAllocatedType().getAsString();
        newNode["isHeapAllocation"] = true;
        newNode["isArray"] = NE->isArray();
        
        // Count arguments: placement args + constructor args
        unsigned numArgs = NE->getNumPlacementArgs();
        if (const CXXConstructExpr* CE = NE->getConstructExpr()) {
            numArgs += CE->getNumArgs();
        }
        newNode["arguments"] = numArgs;
        
        nodes.push_back(newNode);
        nodeIds[NE] = newId;
        objectCreations++;
        
        addEdge(methodId, newId, "CREATES");
        
        // Process placement arguments
        for (unsigned i = 0; i < NE->getNumPlacementArgs(); ++i) {
            processArgument(NE->getPlacementArg(i), newId, i, currentScope);
        }
        
        // Process constructor arguments
        if (const CXXConstructExpr* CE = NE->getConstructExpr()) {
            for (unsigned i = 0; i < CE->getNumArgs(); ++i) {
                processArgument(CE->getArg(i), newId, i + NE->getNumPlacementArgs(), currentScope);
            }
        }
    }

    void processArrayAccess(const ArraySubscriptExpr* ASE, int methodId, const std::string& currentScope) {
        json arrayNode;
        int arrayId = getNextId();
        arrayNode["id"] = arrayId;
        arrayNode["type"] = "ARRAY_ACCESS";
        arrayNode["array"] = getExprString(ASE->getBase(), Context);
        arrayNode["index"] = getExprString(ASE->getIdx(), Context);
        
        // Check for potential buffer overflow
        arrayNode["vulnerability"] = "POTENTIAL_BUFFER_OVERFLOW";
        
        nodes.push_back(arrayNode);
        nodeIds[ASE] = arrayId;
        
        addEdge(methodId, arrayId, "ACCESSES");
        
        // Check if array or index involves tainted data
        checkTaintPropagation(ASE->getBase(), "", arrayId, currentScope);
        checkTaintPropagation(ASE->getIdx(), "", arrayId, currentScope);
    }

void processTryStatement(const CXXTryStmt* TS, int methodId, const std::string& currentScope) {
        json tryNode;
        int tryId = getNextId();
        tryNode["id"] = tryId;
        tryNode["type"] = "TRY_CATCH_BLOCK";
        tryNode["catchClausesCount"] = TS->getNumHandlers();
        tryNode["hasFinallyBlock"] = false; // C++ doesn't have finally
        
        json exceptionTypes = json::array();
        for (unsigned i = 0; i < TS->getNumHandlers(); ++i) {
            const CXXCatchStmt* CS = TS->getHandler(i);
            if (const VarDecl* VD = CS->getExceptionDecl()) {
                exceptionTypes.push_back(VD->getType().getAsString());
            } else {
                exceptionTypes.push_back("catch_all");
            }
        }
        tryNode["exceptionTypes"] = exceptionTypes;
        
        nodes.push_back(tryNode);
        nodeIds[TS] = tryId;
        controlFlows++;
        
        addEdge(methodId, tryId, "CONTAINS");
        
        // Process try block
        if (const CompoundStmt* tryBlock = TS->getTryBlock()) {
            processStmtRecursively(tryBlock, tryId, currentScope);
        }
        
        // Process catch handlers
        for (unsigned i = 0; i < TS->getNumHandlers(); ++i) {
            const CXXCatchStmt* CS = TS->getHandler(i);
            json catchNode;
            int catchId = getNextId();
            catchNode["id"] = catchId;
            catchNode["type"] = "CATCH_CLAUSE";
            
            if (const VarDecl* VD = CS->getExceptionDecl()) {
                catchNode["exceptionType"] = VD->getType().getAsString();
                catchNode["exceptionVariable"] = VD->getNameAsString();
            } else {
                catchNode["exceptionType"] = "catch_all";
            }
            
            nodes.push_back(catchNode);
            addEdge(tryId, catchId, "HANDLES");
            
            // Process catch block
            if (const Stmt* catchBlock = CS->getHandlerBlock()) {
                processStmtRecursively(catchBlock, catchId, currentScope);
            }
        }
    }

    void processReturnStatement(const ReturnStmt* RS, int methodId, const std::string& currentScope) {
        json returnNode;
        int returnId = getNextId();
        returnNode["id"] = returnId;
        returnNode["type"] = "RETURN_STATEMENT";
        
        if (const Expr* RetValue = RS->getRetValue()) {
            returnNode["returnValue"] = getExprString(RetValue, Context);
            returnNode["hasReturnValue"] = true;
            
            // Check if return value is tainted
            checkTaintPropagation(RetValue, "", returnId, currentScope);
        } else {
            returnNode["hasReturnValue"] = false;
        }
        
        nodes.push_back(returnNode);
        nodeIds[RS] = returnId;
        
        addEdge(methodId, returnId, "CONTAINS");
    }

    void processBinaryExpression(const BinaryOperator* BO, int methodId, const std::string& currentScope) {
        json binaryNode;
        int binaryId = getNextId();
        binaryNode["id"] = binaryId;
        binaryNode["type"] = "BINARY_EXPRESSION";
        binaryNode["operator"] = BO->getOpcodeStr().str();
        binaryNode["leftOperand"] = getExprString(BO->getLHS(), Context);
        binaryNode["rightOperand"] = getExprString(BO->getRHS(), Context);
        
        bool isAssignment = BO->isAssignmentOp();
        binaryNode["isAssignment"] = isAssignment;
        
        if (isAssignment) {
            binaryNode["type"] = "ASSIGNMENT";
            assignments++;
            
            // Handle variable assignment for taint tracking
            if (const DeclRefExpr* DRE = dyn_cast<DeclRefExpr>(BO->getLHS())) {
                std::string varName = DRE->getNameInfo().getAsString();
                
                // Create data flow edge from RHS to LHS variable
                if (variableToNodeId.count(varName)) {
                    int varNodeId = variableToNodeId[varName];
                    addEdge(binaryId, varNodeId, "ASSIGNS");
                    dataFlows++;
                    
                    // Propagate taint from RHS to LHS
                    checkTaintPropagation(BO->getRHS(), varName, varNodeId, currentScope);
                }
            }
        }
        
        nodes.push_back(binaryNode);
        nodeIds[BO] = binaryId;
        
        addEdge(methodId, binaryId, "CONTAINS");
        
        // Process operands recursively
        processStmtRecursively(BO->getLHS(), binaryId, currentScope);
        processStmtRecursively(BO->getRHS(), binaryId, currentScope);
    }

    void processUnaryExpression(const UnaryOperator* UO, int methodId, const std::string& currentScope) {
        json unaryNode;
        int unaryId = getNextId();
        unaryNode["id"] = unaryId;
        unaryNode["type"] = "UNARY_EXPRESSION";
        unaryNode["operator"] = UO->getOpcodeStr(UO->getOpcode()).str();
        unaryNode["operand"] = getExprString(UO->getSubExpr(), Context);
        unaryNode["isPrefix"] = UO->isPrefix();
        unaryNode["isPostfix"] = UO->isPostfix();
        
        nodes.push_back(unaryNode);
        nodeIds[UO] = unaryId;
        
        addEdge(methodId, unaryId, "CONTAINS");
        
        // Process operand
        processStmtRecursively(UO->getSubExpr(), unaryId, currentScope);
    }

    void processFieldAccess(const MemberExpr* ME, int methodId, const std::string& currentScope) {
        json fieldNode;
        int fieldId = getNextId();
        fieldNode["id"] = fieldId;
        fieldNode["type"] = "FIELD_ACCESS";
        fieldNode["object"] = getExprString(ME->getBase(), Context);
        fieldNode["fieldName"] = ME->getMemberNameInfo().getAsString();
        fieldNode["isArrow"] = ME->isArrow();
        
        if (const FieldDecl* FD = dyn_cast<FieldDecl>(ME->getMemberDecl())) {
            fieldNode["fieldType"] = FD->getType().getAsString();
        }
        
        nodes.push_back(fieldNode);
        nodeIds[ME] = fieldId;
        
        addEdge(methodId, fieldId, "ACCESSES");
        
        // Check for taint propagation through field access
        checkTaintPropagation(ME->getBase(), "", fieldId, currentScope);
    }

    void processStringLiteral(const StringLiteral* SL, int methodId, const std::string& currentScope) {
        json stringNode;
        int stringId = getNextId();
        stringNode["id"] = stringId;
        stringNode["type"] = "STRING_LITERAL";
        stringNode["value"] = getStringLiteralValue(SL);
        stringNode["length"] = SL->getLength();
        stringNode["isWide"] = SL->isWide();
        
        // Check for potential SQL injection patterns
        std::string value = stringNode["value"];
        if (value.find("SELECT") != std::string::npos ||
            value.find("INSERT") != std::string::npos ||
            value.find("UPDATE") != std::string::npos ||
            value.find("DELETE") != std::string::npos) {
            stringNode["vulnerability"] = "POTENTIAL_SQL_INJECTION";
        }
        
        // Check for command execution patterns
        if (value.find("cmd") != std::string::npos ||
            value.find("sh") != std::string::npos ||
            value.find("/bin/") != std::string::npos) {
            stringNode["vulnerability"] = "POTENTIAL_COMMAND_INJECTION";
        }
        
        nodes.push_back(stringNode);
        nodeIds[SL] = stringId;
        stringLiterals++;
        
        addEdge(methodId, stringId, "CONTAINS");
    }

    void processNumericLiteral(const Stmt* Literal, int methodId, const std::string& type) {
        json numNode;
        int numId = getNextId();
        numNode["id"] = numId;
        numNode["type"] = "NUMERIC_LITERAL";
        numNode["literalType"] = type;
        numNode["value"] = getStmtString(Literal, Context);
        
        nodes.push_back(numNode);
        nodeIds[Literal] = numId;
        
        addEdge(methodId, numId, "CONTAINS");
    }

    void processIfStatement(const IfStmt* IS, int methodId, const std::string& currentScope) {
        json ifNode;
        int ifId = getNextId();
        ifNode["id"] = ifId;
        ifNode["type"] = "IF_STATEMENT";
        ifNode["condition"] = getExprString(IS->getCond(), Context);
        ifNode["hasElse"] = IS->getElse() != nullptr;
        
        nodes.push_back(ifNode);
        nodeIds[IS] = ifId;
        controlFlows++;
        
        addEdge(methodId, ifId, "CONTAINS");
        
        // Process condition
        processStmtRecursively(IS->getCond(), ifId, currentScope);
        
        // Process then branch
        if (const Stmt* thenStmt = IS->getThen()) {
            json thenNode;
            int thenId = getNextId();
            thenNode["id"] = thenId;
            thenNode["type"] = "IF_THEN_BRANCH";
            nodes.push_back(thenNode);
            
            addEdge(ifId, thenId, "THEN");
            processStmtRecursively(thenStmt, thenId, currentScope);
        }
        
        // Process else branch
        if (const Stmt* elseStmt = IS->getElse()) {
            json elseNode;
            int elseId = getNextId();
            elseNode["id"] = elseId;
            elseNode["type"] = "IF_ELSE_BRANCH";
            nodes.push_back(elseNode);
            
            addEdge(ifId, elseId, "ELSE");
            processStmtRecursively(elseStmt, elseId, currentScope);
        }
    }

    void processForStatement(const ForStmt* FS, int methodId, const std::string& currentScope) {
        json forNode;
        int forId = getNextId();
        forNode["id"] = forId;
        forNode["type"] = "FOR_LOOP";
        
        if (const Stmt* init = FS->getInit()) {
            forNode["initializer"] = getStmtString(init, Context);
        }
        if (const Expr* cond = FS->getCond()) {
            forNode["condition"] = getExprString(cond, Context);
        }
        if (const Expr* inc = FS->getInc()) {
            forNode["increment"] = getExprString(inc, Context);
        }
        
        nodes.push_back(forNode);
        nodeIds[FS] = forId;
        controlFlows++;
        
        addEdge(methodId, forId, "CONTAINS");
        
        // Process components
        if (const Stmt* init = FS->getInit()) {
            processStmtRecursively(init, forId, currentScope);
        }
        if (const Expr* cond = FS->getCond()) {
            processStmtRecursively(cond, forId, currentScope);
        }
        if (const Expr* inc = FS->getInc()) {
            processStmtRecursively(inc, forId, currentScope);
        }
        
        // Process body
        if (const Stmt* body = FS->getBody()) {
            json bodyNode;
            int bodyId = getNextId();
            bodyNode["id"] = bodyId;
            bodyNode["type"] = "FOR_BODY";
            nodes.push_back(bodyNode);
            
            addEdge(forId, bodyId, "BODY");
            processStmtRecursively(body, bodyId, currentScope);
        }
    }

    void processWhileStatement(const WhileStmt* WS, int methodId, const std::string& currentScope) {
        json whileNode;
        int whileId = getNextId();
        whileNode["id"] = whileId;
        whileNode["type"] = "WHILE_LOOP";
        whileNode["condition"] = getExprString(WS->getCond(), Context);
        
        nodes.push_back(whileNode);
        nodeIds[WS] = whileId;
        controlFlows++;
        
        addEdge(methodId, whileId, "CONTAINS");
        
        // Process condition
        processStmtRecursively(WS->getCond(), whileId, currentScope);
        
        // Process body
        if (const Stmt* body = WS->getBody()) {
            json bodyNode;
            int bodyId = getNextId();
            bodyNode["id"] = bodyId;
            bodyNode["type"] = "WHILE_BODY";
            nodes.push_back(bodyNode);
            
            addEdge(whileId, bodyId, "BODY");
            processStmtRecursively(body, bodyId, currentScope);
        }
    }

    void processDoWhileStatement(const DoStmt* DS, int methodId, const std::string& currentScope) {
        json doWhileNode;
        int doWhileId = getNextId();
        doWhileNode["id"] = doWhileId;
        doWhileNode["type"] = "DO_WHILE_LOOP";
        doWhileNode["condition"] = getExprString(DS->getCond(), Context);
        
        nodes.push_back(doWhileNode);
        nodeIds[DS] = doWhileId;
        controlFlows++;
        
        addEdge(methodId, doWhileId, "CONTAINS");
        
        // Process body first (do-while executes body before condition)
        if (const Stmt* body = DS->getBody()) {
            json bodyNode;
            int bodyId = getNextId();
            bodyNode["id"] = bodyId;
            bodyNode["type"] = "DO_WHILE_BODY";
            nodes.push_back(bodyNode);
            
            addEdge(doWhileId, bodyId, "BODY");
            processStmtRecursively(body, bodyId, currentScope);
        }
        
        // Process condition
        processStmtRecursively(DS->getCond(), doWhileId, currentScope);
    }

    void processForEachStatement(const CXXForRangeStmt* FRS, int methodId, const std::string& currentScope) {
        json forEachNode;
        int forEachId = getNextId();
        forEachNode["id"] = forEachId;
        forEachNode["type"] = "FOR_EACH_LOOP";
        forEachNode["range"] = getExprString(FRS->getRangeInit(), Context);
        
        if (const VarDecl* VD = FRS->getLoopVariable()) {
            forEachNode["loopVariable"] = VD->getNameAsString();
            forEachNode["loopVariableType"] = VD->getType().getAsString();
        }
        
        nodes.push_back(forEachNode);
        nodeIds[FRS] = forEachId;
        controlFlows++;
        
        addEdge(methodId, forEachId, "CONTAINS");
        
        // Process range expression
        processStmtRecursively(FRS->getRangeInit(), forEachId, currentScope);
        
        // Process body
        if (const Stmt* body = FRS->getBody()) {
            json bodyNode;
            int bodyId = getNextId();
            bodyNode["id"] = bodyId;
            bodyNode["type"] = "FOR_EACH_BODY";
            nodes.push_back(bodyNode);
            
            addEdge(forEachId, bodyId, "BODY");
            processStmtRecursively(body, bodyId, currentScope);
        }
    }

    void processSwitchStatement(const SwitchStmt* SS, int methodId, const std::string& currentScope) {
        json switchNode;
        int switchId = getNextId();
        switchNode["id"] = switchId;
        switchNode["type"] = "SWITCH_STATEMENT";
        switchNode["condition"] = getExprString(SS->getCond(), Context);
        
        nodes.push_back(switchNode);
        nodeIds[SS] = switchId;
        controlFlows++;
        
        addEdge(methodId, switchId, "CONTAINS");
        
        // Process condition
        processStmtRecursively(SS->getCond(), switchId, currentScope);
        
        // Process body (contains case statements)
        if (const Stmt* body = SS->getBody()) {
            processStmtRecursively(body, switchId, currentScope);
        }
    }

    void processArgument(const Expr* Arg, int callId, int argIndex, const std::string& currentScope) {
        json argNode;
        int argId = getNextId();
        argNode["id"] = argId;
        argNode["type"] = "ARGUMENT";
        argNode["index"] = argIndex;
        argNode["expression"] = getExprString(Arg, Context);
        
        nodes.push_back(argNode);
        nodeIds[Arg] = argId;
        
        addEdge(callId, argId, "HAS_ARGUMENT");
        
        // Check for taint propagation through arguments
        checkTaintPropagation(Arg, "", argId, currentScope);
        
        // Process argument expression recursively
        processStmtRecursively(Arg, argId, currentScope);
    }

    void markVariableAsTainted(const std::string& varName, int nodeId, const std::string& source) {
        TaintInfo taint;
        taint.nodeId = nodeId;
        taint.source = source;
        taint.isTainted = true;
        taint.propagationPath.push_back(source);
        
        taintedVariables[varName] = taint;
    }

    void checkTaintPropagation(const Expr* expr, const std::string& targetVar, int targetNodeId, const std::string& currentScope) {
        if (!expr) return;
        
        // Check if expression references a tainted variable
        if (const DeclRefExpr* DRE = dyn_cast<DeclRefExpr>(expr)) {
            std::string varName = DRE->getNameInfo().getAsString();
            
            if (taintedVariables.count(varName) && taintedVariables[varName].isTainted) {
                // Propagate taint to target variable
                if (!targetVar.empty()) {
                    TaintInfo newTaint = taintedVariables[varName];
                    newTaint.nodeId = targetNodeId;
                    newTaint.propagationPath.push_back(targetVar);
                    taintedVariables[targetVar] = newTaint;
                    
                    // Create data flow edge
                    addEdge(taintedVariables[varName].nodeId, targetNodeId, "DATA_FLOW");
                    dataFlows++;
                }
                
                // Mark the expression node as tainted
                if (nodeIds.count(expr)) {
                    json& node = findNodeById(nodeIds[expr]);
                    node["isTainted"] = true;
                    node["taintSource"] = taintedVariables[varName].source;
                }
            }
        }
        
        // Recursively check sub-expressions
        for (auto it = expr->child_begin(); it != expr->child_end(); ++it) {
            if (const Expr* childExpr = dyn_cast<Expr>(*it)) {
                checkTaintPropagation(childExpr, targetVar, targetNodeId, currentScope);
            }
        }
    }

    void checkTaintedArgumentToSink(const Expr* arg, int callId, const std::string& functionName, int argIndex) {
        if (const DeclRefExpr* DRE = dyn_cast<DeclRefExpr>(arg)) {
            std::string varName = DRE->getNameInfo().getAsString();
            
            if (taintedVariables.count(varName) && taintedVariables[varName].isTainted) {
                // Found tainted data flowing to a sink!
                json vulnNode;
                int vulnId = getNextId();
                vulnNode["id"] = vulnId;
                vulnNode["type"] = "VULNERABILITY";
                vulnNode["category"] = "TAINT_FLOW";
                vulnNode["severity"] = "HIGH";
                vulnNode["sinkFunction"] = functionName;
                vulnNode["taintedVariable"] = varName;
                vulnNode["taintSource"] = taintedVariables[varName].source;
                vulnNode["argumentIndex"] = argIndex;
                
                // Determine specific vulnerability type
                if (functionName == "system" || functionName.find("exec") != std::string::npos) {
                    vulnNode["vulnerabilityType"] = "COMMAND_INJECTION";
                    vulnNode["cwe"] = "CWE-78";
                } else if (functionName.find("sql") != std::string::npos || functionName.find("query") != std::string::npos) {
                    vulnNode["vulnerabilityType"] = "SQL_INJECTION";
                    vulnNode["cwe"] = "CWE-89";
                } else if (functionName == "strcpy" || functionName == "strcat" || functionName == "sprintf") {
                    vulnNode["vulnerabilityType"] = "BUFFER_OVERFLOW";
                    vulnNode["cwe"] = "CWE-120";
                } else {
                    vulnNode["vulnerabilityType"] = "GENERIC_INJECTION";
                    vulnNode["cwe"] = "CWE-94";
                }
                
                vulnNode["propagationPath"] = json::array();
                for (const std::string& step : taintedVariables[varName].propagationPath) {
                    vulnNode["propagationPath"].push_back(step);
                }
                vulnNode["propagationPath"].push_back(functionName);
                
                nodes.push_back(vulnNode);
                
                // Link vulnerability to the call
                addEdge(callId, vulnId, "CAUSES");
                addEdge(taintedVariables[varName].nodeId, vulnId, "TAINT_FLOW");
            }
        }
    }

    json& findNodeById(int id) {
        for (auto& node : nodes) {
            if (node["id"] == id) {
                return node;
            }
        }
        // Return first node if not found (should not happen)
        return nodes[0];
    }
};

// Consumer and Action classes
class EnhancedCodeGraphConsumer : public ASTConsumer {
public:
    explicit EnhancedCodeGraphConsumer(ASTContext* Context) : Visitor(Context) {}

    void HandleTranslationUnit(ASTContext& Context) override {
        Visitor.TraverseDecl(Context.getTranslationUnitDecl());
    }

private:
    EnhancedCodeGraphVisitor Visitor;
};

class EnhancedCodeGraphAction : public ASTFrontendAction {
public:
    std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance& CI, StringRef file) override {
        return std::make_unique<EnhancedCodeGraphConsumer>(&CI.getASTContext());
    }
};

// HTTP upload functionality
size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

bool uploadResults(const std::string& jsonData, const std::string& endpoint) {
    CURL* curl;
    CURLcode res;
    std::string readBuffer;
    
    curl = curl_easy_init();
    if (curl) {
        struct curl_slist* headers = nullptr;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        
        curl_easy_setopt(curl, CURLOPT_URL, endpoint.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonData.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        
        res = curl_easy_perform(curl);
        
        if (res != CURLE_OK) {
            std::cerr << "Upload failed: " << curl_easy_strerror(res) << std::endl;
            curl_slist_free_all(headers);
            curl_easy_cleanup(curl);
            return false;
        }
        
        long response_code;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
        
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        
        if (response_code >= 200 && response_code < 300) {
            std::cout << "Successfully uploaded results to " << endpoint << std::endl;
            return true;
        } else {
            std::cerr << "Upload failed with HTTP " << response_code << std::endl;
            return false;
        }
    }
    
    return false;
}

void generateCodeGraph() {
    // Create metadata
    json metadata;
    metadata["scanner"] = "enhanced-cpp-scanner";
    metadata["version"] = "2.0.0";
    metadata["timestamp"] = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    metadata["language"] = "C++";
    
    // Create statistics
    json statistics;
    statistics["totalNodes"] = nodes.size();
    statistics["totalEdges"] = edges.size();
    statistics["methodCalls"] = methodCalls;
    statistics["assignments"] = assignments;
    statistics["stringLiterals"] = stringLiterals;
    statistics["controlFlows"] = controlFlows;
    statistics["objectCreations"] = objectCreations;
    statistics["taintSources"] = taintSources;
    statistics["taintSinks"] = taintSinks;
    statistics["dataFlows"] = dataFlows;
    statistics["taintedVariables"] = taintedVariables.size();
    
    // Count vulnerabilities
    int vulnerabilityCount = 0;
    for (const auto& node : nodes) {
        if (node["type"] == "VULNERABILITY") {
            vulnerabilityCount++;
        }
    }
    statistics["vulnerabilities"] = vulnerabilityCount;
    
    // Create final graph structure
    codeGraph["metadata"] = metadata;
    codeGraph["statistics"] = statistics;
    codeGraph["nodes"] = nodes;
    codeGraph["edges"] = edges;
    codeGraph["graphId"] = generateUUID();
    
    // Add taint analysis results
    json taintAnalysis;
    taintAnalysis["taintedVariables"] = json::object();
    for (const auto& [varName, taintInfo] : taintedVariables) {
        json taintJson;
        taintJson["nodeId"] = taintInfo.nodeId;
        taintJson["source"] = taintInfo.source;
        taintJson["isTainted"] = taintInfo.isTainted;
        taintJson["propagationPath"] = taintInfo.propagationPath;
        taintAnalysis["taintedVariables"][varName] = taintJson;
    }
    codeGraph["taintAnalysis"] = taintAnalysis;
}

void saveResultsLocally(const std::string& filePath) {
    std::ofstream outFile(filePath);
    if (outFile.is_open()) {
        outFile << codeGraph.dump(2);
        outFile.close();
        std::cout << "Results saved to: " << filePath << std::endl;
    } else {
        std::cerr << "Error: Could not open file for writing: " << filePath << std::endl;
    }
}

int main(int argc, const char** argv) {
    // Initialize curl for HTTP uploads
    curl_global_init(CURL_GLOBAL_DEFAULT);
    
    auto ExpectedParser = CommonOptionsParser::create(argc, argv, CppScannerCategory);
    if (!ExpectedParser) {
        llvm::errs() << ExpectedParser.takeError();
        return 1;
    }
    CommonOptionsParser& OptionsParser = ExpectedParser.get();
    
    // Parse command line options
    if (SaveLocal.getValue()) {
        saveLocal = true;
    }
    if (!OutputPath.getValue().empty()) {
        outputPath = OutputPath.getValue();
    }
    if (!ApiEndpoint.getValue().empty()) {
        apiEndpoint = ApiEndpoint.getValue();
    }
    
    // Create and run the tool
    ClangTool Tool(OptionsParser.getCompilations(), OptionsParser.getSourcePathList());
    
    std::cout << "Enhanced C++ Code Scanner v2.0" << std::endl;
    std::cout << "Processing files..." << std::endl;
    
    int result = Tool.run(newFrontendActionFactory<EnhancedCodeGraphAction>().get());
    
    if (result == 0) {
        std::cout << "AST processing completed successfully." << std::endl;
        
        // Generate the final code graph
        generateCodeGraph();
        
        std::cout << "\n=== SCAN RESULTS ===" << std::endl;
        std::cout << "Total nodes: " << nodes.size() << std::endl;
        std::cout << "Total edges: " << edges.size() << std::endl;
        std::cout << "Method calls: " << methodCalls << std::endl;
        std::cout << "Assignments: " << assignments << std::endl;
        std::cout << "String literals: " << stringLiterals << std::endl;
        std::cout << "Control flows: " << controlFlows << std::endl;
        std::cout << "Object creations: " << objectCreations << std::endl;
        std::cout << "Taint sources: " << taintSources << std::endl;
        std::cout << "Taint sinks: " << taintSinks << std::endl;
        std::cout << "Data flows: " << dataFlows << std::endl;
        std::cout << "Tainted variables: " << taintedVariables.size() << std::endl;
        
        // Count and display vulnerabilities
        int vulnerabilityCount = 0;
        for (const auto& node : nodes) {
            if (node["type"] == "VULNERABILITY") {
                vulnerabilityCount++;
            }
        }
        std::cout << "Potential vulnerabilities found: " << vulnerabilityCount << std::endl;

        // Output the results
        if (saveLocal) {
            saveResultsLocally(outputPath);
        } else {
            std::cout << "Uploading results to " << apiEndpoint << "..." << std::endl;
            if (!uploadResults(codeGraph.dump(), apiEndpoint)) {
                std::cerr << "Upload failed, saving results locally as fallback..." << std::endl;
                saveResultsLocally("fallback_" + outputPath);
            }
        }
    } else {
        std::cerr << "AST processing encountered errors." << std::endl;
    }

    // Clean up curl
    curl_global_cleanup();

    return result;
}