import com.github.javaparser.JavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.*;
import com.github.javaparser.ast.expr.*;
import com.github.javaparser.ast.stmt.*;
import com.github.javaparser.utils.SourceRoot;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.io.OutputStream;

public class scanner_test {

    private static String apiEndpoint = "http://localhost:8080/api/upload";
    private static boolean saveLocal = false;
    private static String outputPath = "codegraph.json";

    public static void main(String[] args) throws IOException {
        if (args.length < 1) {
            System.out.println("Usage: java JSentinelCliScanner <path-to-java-source> [--local] [--output path.json] [--endpoint url]");
            return;
        }

        parseArguments(args);
        Path sourcePath = new File(args[0]).toPath().toAbsolutePath();

        if (!sourcePath.toFile().exists()) {
            System.err.println("Error: Source path does not exist: " + sourcePath);
            return;
        }

        System.out.println("Scanning source path: " + sourcePath);

        SourceRoot sourceRoot = new SourceRoot(sourcePath);
        JSONObject codeGraph = new JSONObject();
        codeGraph.put("scanId", UUID.randomUUID().toString());
        codeGraph.put("timestamp", System.currentTimeMillis());

        JSONArray nodes = new JSONArray();
        JSONArray edges = new JSONArray();
        codeGraph.put("nodes", nodes);
        codeGraph.put("edges", edges);

        Map<Node, Integer> nodeIds = new HashMap<>();
        AtomicInteger nextId = new AtomicInteger(1);

        JSONArray potentialLogInjections = new JSONArray();
        JSONArray inefficientListOperations = new JSONArray();
        JSONArray missingInputValidations = new JSONArray();
        JSONArray constructorNamingIssues = new JSONArray();
        JSONArray sensitiveDataExposures = new JSONArray();
        JSONArray overlyBroadCatches = new JSONArray();

        try {
            sourceRoot.tryToParse().forEach(result -> {
                result.ifSuccessful(cu -> {
                    String fileName = cu.getStorage().map(s -> s.getFileName()).orElse("Unknown");

                    JSONObject fileNode = new JSONObject();
                    fileNode.put("id", nextId.get());
                    fileNode.put("type", "FILE");
                    fileNode.put("name", fileName);
                    nodes.put(fileNode);
                    nodeIds.put(cu, nextId.getAndIncrement());

                    cu.findAll(ClassOrInterfaceDeclaration.class).forEach(cls -> {
                        JSONObject classNode = new JSONObject();
                        classNode.put("id", nextId.get());
                        classNode.put("type", cls.isInterface() ? "INTERFACE" : "CLASS");
                        classNode.put("name", cls.getNameAsString());
                        nodes.put(classNode);
                        nodeIds.put(cls, nextId.getAndIncrement());

                        edges.put(createEdge(nodeIds.get(cu), nodeIds.get(cls), "CONTAINS"));

                        cls.getConstructors().forEach(constructor -> {
                            JSONObject constructorNode = new JSONObject();
                            constructorNode.put("id", nextId.get());
                            constructorNode.put("type", "CONSTRUCTOR");
                            constructorNode.put("name", constructor.getNameAsString());
                            constructorNode.put("parameters", constructor.getParameters().size());
                            nodes.put(constructorNode);
                            nodeIds.put(constructor, nextId.getAndIncrement());

                            edges.put(createEdge(nodeIds.get(cls), nodeIds.get(constructor), "CONTAINS"));

                            if (!constructor.getNameAsString().equals(cls.getNameAsString())) {
                                JSONObject issue = new JSONObject();
                                issue.put("constructorId", nodeIds.get(constructor));
                                issue.put("className", cls.getNameAsString());
                                issue.put("constructorName", constructor.getNameAsString());
                                issue.put("message", "Constructor name does not match class name");
                                constructorNamingIssues.put(issue);
                            }

                            analyzeMethodBody(constructor, nodeIds, nodes, edges, nextId, potentialLogInjections, 
                                              inefficientListOperations, sensitiveDataExposures, overlyBroadCatches);
                        });

                        cls.getMethods().forEach(method -> {
                            JSONObject methodNode = new JSONObject();
                            methodNode.put("id", nextId.get());
                            methodNode.put("type", "METHOD");
                            methodNode.put("name", method.getNameAsString());
                            methodNode.put("returnType", method.getType().asString());
                            methodNode.put("parameters", method.getParameters().size());
                            nodes.put(methodNode);
                            nodeIds.put(method, nextId.getAndIncrement());

                            edges.put(createEdge(nodeIds.get(cls), nodeIds.get(method), "CONTAINS"));

                            List<String> paramNames = new ArrayList<>();
                            List<String> nonPrimitiveParams = new ArrayList<>();
                            List<String> stringOrCollectionParams = new ArrayList<>();
                            for (Parameter param : method.getParameters()) {
                                String paramName = param.getNameAsString();
                                paramNames.add(paramName);
                                String paramType = param.getType().asString();
                                if (!param.getType().isPrimitiveType()) {
                                    nonPrimitiveParams.add(paramName);
                                }
                                if (paramType.equals("String") || paramType.contains("List") || 
                                    paramType.contains("Set") || paramType.contains("Map")) {
                                    stringOrCollectionParams.add(paramName);
                                }
                            }
                            Optional<BlockStmt> methodBody = method instanceof MethodDeclaration ? ((MethodDeclaration) method).getBody() : Optional.empty();
                            methodBody.ifPresent(body -> {
                                boolean foundNullCheck = false;
                                boolean foundLengthCheck = false;
                                for (String paramName : paramNames) {
                                    foundNullCheck |= body.findAll(IfStmt.class).stream().anyMatch(ifStmt -> 
                                        ifStmt.getCondition().toString().contains(paramName + " == null") ||
                                        ifStmt.getCondition().toString().contains("null == " + paramName));
                                    foundLengthCheck |= body.findAll(MethodCallExpr.class).stream().anyMatch(call ->
                                        call.getNameAsString().equals("length") && call.toString().contains(paramName + ".length")) ||
                                        body.findAll(MethodCallExpr.class).stream().anyMatch(call ->
                                        call.getNameAsString().equals("isEmpty") && call.toString().contains(paramName + ".isEmpty"));
                                }
                                if (!nonPrimitiveParams.isEmpty() && !foundNullCheck) {
                                    JSONObject issue = new JSONObject();
                                    issue.put("methodId", nodeIds.get(method));
                                    issue.put("methodName", method.getNameAsString());
                                    issue.put("message", "Missing null check for parameters: " + String.join(", ", nonPrimitiveParams));
                                    issue.put("suggestedFix", "Add null check: if (" + nonPrimitiveParams.get(0) + " == null) { throw new IllegalArgumentException(\"Parameter cannot be null\"); }");
                                    missingInputValidations.put(issue);
                                }
                                if (!stringOrCollectionParams.isEmpty() && !foundLengthCheck) {
                                    JSONObject issue = new JSONObject();
                                    issue.put("methodId", nodeIds.get(method));
                                    issue.put("methodName", method.getNameAsString());
                                    issue.put("message", "Missing length/isEmpty check for parameters: " + String.join(", ", stringOrCollectionParams));
                                    issue.put("suggestedFix", "Add validation: if (" + stringOrCollectionParams.get(0) + ".isEmpty()) { throw new IllegalArgumentException(\"Parameter cannot be empty\"); }");
                                    missingInputValidations.put(issue);
                                }
                            });

                            analyzeMethodBody(method, nodeIds, nodes, edges, nextId, potentialLogInjections, 
                                              inefficientListOperations, sensitiveDataExposures, overlyBroadCatches);
                        });

                        cls.getFields().forEach(field -> {
                            field.getVariables().forEach(variable -> {
                                JSONObject varNode = new JSONObject();
                                varNode.put("id", nextId.get());
                                varNode.put("type", "FIELD");
                                varNode.put("name", variable.getNameAsString());
                                varNode.put("dataType", field.getElementType().asString());
                                nodes.put(varNode);
                                nodeIds.put(variable, nextId.getAndIncrement());

                                edges.put(createEdge(nodeIds.get(cls), nodeIds.get(variable), "DECLARES"));
                            });
                        });
                    });

                    analyzeGlobalElements(cu, nodeIds, nodes, edges, nextId);
                });
            });
        } catch (Exception e) {
            System.err.println("Error parsing source files: " + e.getMessage());
            e.printStackTrace();
            return;
        }

        JSONObject stats = new JSONObject();
        stats.put("totalNodes", nodes.length());
        stats.put("totalEdges", edges.length());

        int methodCalls = 0, assignments = 0, stringLiterals = 0, controlFlows = 0;
        for (int i = 0; i < nodes.length(); i++) {
            JSONObject node = nodes.getJSONObject(i);
            String type = node.getString("type");
            switch (type) {
                case "METHOD_CALL": methodCalls++; break;
                case "ASSIGNMENT": assignments++; break;
                case "STRING_LITERAL": stringLiterals++; break;
                case "IF_STATEMENT":
                case "FOR_LOOP":
                case "WHILE_LOOP": controlFlows++; break;
            }
        }
        for (int i = 0; i < nodes.length(); i++) {
            JSONObject node = nodes.getJSONObject(i);
            String type = node.getString("type");
            if (type.equals("LOCAL_VARIABLE") || type.equals("FIELD")) {
                if (node.has("initializer")) {
                    assignments++;
                }
            }
        }

        stats.put("methodCalls", methodCalls);
        stats.put("assignments", assignments);
        stats.put("stringLiterals", stringLiterals);
        stats.put("controlFlowNodes", controlFlows);
        stats.put("potentialLogInjections", potentialLogInjections.length());
        stats.put("inefficientListOperations", inefficientListOperations.length());
        stats.put("missingInputValidations", missingInputValidations.length());
        stats.put("constructorNamingIssues", constructorNamingIssues.length());
        stats.put("sensitiveDataExposures", sensitiveDataExposures.length());
        stats.put("overlyBroadCatches", overlyBroadCatches.length());

        codeGraph.put("potentialLogInjections", potentialLogInjections);
        codeGraph.put("inefficientListOperations", inefficientListOperations);
        codeGraph.put("missingInputValidations", missingInputValidations);
        codeGraph.put("constructorNamingIssues", constructorNamingIssues);
        codeGraph.put("sensitiveDataExposures", sensitiveDataExposures);
        codeGraph.put("overlyBroadCatches", overlyBroadCatches);
        codeGraph.put("statistics", stats);

        if (saveLocal) {
            saveGraphLocally(codeGraph);
        } else {
            uploadGraph(codeGraph);
        }
    }

    private static void analyzeMethodBody(CallableDeclaration<?> method, Map<Node, Integer> nodeIds, 
                                         JSONArray nodes, JSONArray edges, AtomicInteger nextId,
                                         JSONArray potentialLogInjections, JSONArray inefficientListOperations,
                                         JSONArray sensitiveDataExposures, JSONArray overlyBroadCatches) {
        Integer methodId = nodeIds.get(method);
        if (methodId == null) return;

        Optional<BlockStmt> body = Optional.empty();
        if (method instanceof MethodDeclaration) {
            body = ((MethodDeclaration) method).getBody();
        } else if (method instanceof ConstructorDeclaration) {
            body = Optional.of(((ConstructorDeclaration) method).getBody());
        }

        body.ifPresent(b -> {
            // Track variables for data flow
            Map<String, Integer> variableToNodeId = new HashMap<>();
            b.findAll(VariableDeclarator.class).forEach(varDeclarator -> {
                variableToNodeId.put(varDeclarator.getNameAsString(), nodeIds.get(varDeclarator));
            });

            // Analyze method parameters as potential taint sources
            if (method instanceof MethodDeclaration) {
                ((MethodDeclaration) method).getParameters().forEach(param -> {
                    if (param.getType().asString().equals("String")) {
                        JSONObject paramNode = new JSONObject();
                        paramNode.put("id", nextId.get());
                        paramNode.put("type", "PARAMETER");
                        paramNode.put("name", param.getNameAsString());
                        paramNode.put("dataType", param.getType().asString());
                        nodes.put(paramNode);
                        nodeIds.put(param, nextId.getAndIncrement());
                        edges.put(createEdge(methodId, nodeIds.get(param), "DECLARES"));
                    }
                });
            }

            b.findAll(MethodCallExpr.class).forEach(methodCall -> {
                JSONObject callNode = new JSONObject();
                callNode.put("id", nextId.get());
                callNode.put("type", "METHOD_CALL");
                callNode.put("name", methodCall.getNameAsString());
                callNode.put("arguments", methodCall.getArguments().size());
                methodCall.getScope().ifPresent(scope -> {
                    callNode.put("scope", scope.toString());
                });
                nodes.put(callNode);
                nodeIds.put(methodCall, nextId.getAndIncrement());

                edges.put(createEdge(methodId, nodeIds.get(methodCall), "INVOKES"));

                // Add DATA_FLOW edges for method call arguments
                methodCall.getArguments().forEach(arg -> {
                    if (arg instanceof NameExpr) {
                        String varName = ((NameExpr) arg).getNameAsString();
                        Integer varNodeId = variableToNodeId.get(varName);
                        if (varNodeId != null) {
                            edges.put(createEdge(varNodeId, nodeIds.get(methodCall), "DATA_FLOW"));
                        }
                    }
                });

                String methodName = methodCall.getNameAsString();
                if (methodName.equals("println") || methodName.equals("print") ||
                    methodName.equals("info") || methodName.equals("debug") ||
                    methodName.equals("warn") || methodName.equals("warning") ||
                    methodName.equals("error") || methodName.equals("log")) {
                    for (Expression arg : methodCall.getArguments()) {
                        if (arg instanceof BinaryExpr) {
                            BinaryExpr binaryExpr = (BinaryExpr) arg;
                            if (binaryExpr.getOperator() == BinaryExpr.Operator.PLUS) {
                                boolean involvesVariable = binaryExpr.findAll(NameExpr.class).stream().anyMatch(nameExpr -> {
                                    String name = nameExpr.getNameAsString();
                                    return b.findAll(VariableDeclarator.class).stream().anyMatch(var -> var.getNameAsString().equals(name)) ||
                                           method.getParameters().stream().anyMatch(param -> param.getNameAsString().equals(name));
                                }) || binaryExpr.findAll(FieldAccessExpr.class).stream().anyMatch(fieldAccess -> true);
                                if (involvesVariable) {
                                    JSONObject issue = new JSONObject();
                                    issue.put("methodCallId", nodeIds.get(methodCall));
                                    issue.put("methodName", method.getNameAsString());
                                    issue.put("message", "Potential log injection: " + methodName + " with string concatenation involving variables");
                                    issue.put("severity", methodName.equals("println") || methodName.equals("print") ? "Low" : "High");
                                    issue.put("suggestedFix", "Sanitize input before concatenation, e.g., replaceAll(\"[\\n\\r]\", \"\")");
                                    potentialLogInjections.put(issue);
                                }
                            }
                        }
                    }
                }
            });

            b.findAll(BinaryExpr.class).forEach(binaryExpr -> {
                JSONObject exprNode = new JSONObject();
                exprNode.put("id", nextId.get());
                exprNode.put("type", "BINARY_EXPRESSION");
                exprNode.put("operator", binaryExpr.getOperator().asString());
                exprNode.put("leftOperand", binaryExpr.getLeft().toString());
                exprNode.put("rightOperand", binaryExpr.getRight().toString());
                nodes.put(exprNode);
                nodeIds.put(binaryExpr, nextId.getAndIncrement());

                edges.put(createEdge(methodId, nodeIds.get(binaryExpr), "CONTAINS_EXPRESSION"));
            });

            b.findAll(IfStmt.class).forEach(ifStmt -> {
                JSONObject ifNode = new JSONObject();
                ifNode.put("id", nextId.get());
                ifNode.put("type", "IF_STATEMENT");
                ifNode.put("condition", ifStmt.getCondition().toString());
                ifNode.put("hasElse", ifStmt.getElseStmt().isPresent());
                nodes.put(ifNode);
                nodeIds.put(ifStmt, nextId.getAndIncrement());

                edges.put(createEdge(methodId, nodeIds.get(ifStmt), "CONTAINS_CONTROL_FLOW"));
            });

            b.findAll(ForStmt.class).forEach(forStmt -> {
                JSONObject forNode = new JSONObject();
                forNode.put("id", nextId.get());
                forNode.put("type", "FOR_LOOP");
                forStmt.getCompare().ifPresent(compare -> 
                    forNode.put("condition", compare.toString()));
                nodes.put(forNode);
                nodeIds.put(forStmt, nextId.getAndIncrement());

                edges.put(createEdge(methodId, nodeIds.get(forStmt), "CONTAINS_CONTROL_FLOW"));

                forStmt.getBody().findAll(MethodCallExpr.class).forEach(call -> {
                    if (call.getNameAsString().equals("remove") && call.getArguments().size() == 1 && call.getArguments().get(0).toString().equals("0")) {
                        JSONObject issue = new JSONObject();
                        issue.put("loopId", nodeIds.get(forStmt));
                        issue.put("methodName", method.getNameAsString());
                        issue.put("message", "Inefficient list operation: remove(0) in a for loop");
                        issue.put("suggestedFix", "Use list.clear() to remove all elements efficiently");
                        inefficientListOperations.put(issue);
                    }
                });
            });

            b.findAll(ForEachStmt.class).forEach(forEachStmt -> {
                JSONObject forEachNode = new JSONObject();
                forEachNode.put("id", nextId.get());
                forEachNode.put("type", "FOR_EACH_LOOP");
                forEachNode.put("variable", forEachStmt.getVariable().toString());
                forEachNode.put("iterable", forEachStmt.getIterable().toString());
                nodes.put(forEachNode);
                nodeIds.put(forEachStmt, nextId.getAndIncrement());

                edges.put(createEdge(methodId, nodeIds.get(forEachStmt), "CONTAINS_CONTROL_FLOW"));

                forEachStmt.getBody().findAll(MethodCallExpr.class).forEach(call -> {
                    if (call.getNameAsString().equals("remove") && call.getArguments().size() == 1 && call.getArguments().get(0).toString().equals("0")) {
                        JSONObject issue = new JSONObject();
                        issue.put("loopId", nodeIds.get(forEachStmt));
                        issue.put("methodName", method.getNameAsString());
                        issue.put("message", "Inefficient list operation: remove(0) in a for-each loop (may also cause ConcurrentModificationException)");
                        issue.put("suggestedFix", "Use list.clear() or a different loop structure to remove elements");
                        inefficientListOperations.put(issue);
                    }
                });
            });

            b.findAll(WhileStmt.class).forEach(whileStmt -> {
                JSONObject whileNode = new JSONObject();
                whileNode.put("id", nextId.get());
                whileNode.put("type", "WHILE_LOOP");
                whileNode.put("condition", whileStmt.getCondition().toString());
                nodes.put(whileNode);
                nodeIds.put(whileStmt, nextId.getAndIncrement());

                edges.put(createEdge(methodId, nodeIds.get(whileStmt), "CONTAINS_CONTROL_FLOW"));

                whileStmt.getBody().findAll(MethodCallExpr.class).forEach(call -> {
                    if (call.getNameAsString().equals("remove") && call.getArguments().size() == 1 && call.getArguments().get(0).toString().equals("0")) {
                        JSONObject issue = new JSONObject();
                        issue.put("loopId", nodeIds.get(whileStmt));
                        issue.put("methodName", method.getNameAsString());
                        issue.put("message", "Inefficient list operation: remove(0) in a while loop");
                        issue.put("suggestedFix", "Use list.clear() to remove all elements efficiently");
                        inefficientListOperations.put(issue);
                    }
                });
            });

            b.findAll(VariableDeclarator.class).forEach(varDeclarator -> {
                JSONObject varNode = new JSONObject();
                varNode.put("id", nextId.get());
                varNode.put("type", "LOCAL_VARIABLE");
                varNode.put("name", varDeclarator.getNameAsString());
                varNode.put("dataType", varDeclarator.getType().asString());

                varDeclarator.getInitializer().ifPresent(init -> 
                    varNode.put("initializer", init.toString()));

                nodes.put(varNode);
                nodeIds.put(varDeclarator, nextId.getAndIncrement());

                edges.put(createEdge(methodId, nodeIds.get(varDeclarator), "DECLARES"));

                // Add DATA_FLOW edge for initializer
                varDeclarator.getInitializer().ifPresent(init -> {
                    init.findAll(NameExpr.class).forEach(nameExpr -> {
                        String varName = nameExpr.getNameAsString();
                        Integer sourceNodeId = variableToNodeId.get(varName);
                        if (sourceNodeId != null) {
                            edges.put(createEdge(sourceNodeId, nodeIds.get(varDeclarator), "DATA_FLOW"));
                        }
                    });
                });
            });

            b.findAll(AssignExpr.class).forEach(assignExpr -> {
                JSONObject assignNode = new JSONObject();
                assignNode.put("id", nextId.get());
                assignNode.put("type", "ASSIGNMENT");
                assignNode.put("target", assignExpr.getTarget().toString());
                assignNode.put("value", assignExpr.getValue().toString());
                assignNode.put("operator", assignExpr.getOperator().asString());
                nodes.put(assignNode);
                nodeIds.put(assignExpr, nextId.getAndIncrement());

                edges.put(createEdge(methodId, nodeIds.get(assignExpr), "CONTAINS_ASSIGNMENT"));

                // Add DATA_FLOW edge for assignment
                assignExpr.getValue().findAll(NameExpr.class).forEach(nameExpr -> {
                    String varName = nameExpr.getNameAsString();
                    Integer sourceNodeId = variableToNodeId.get(varName);
                    if (sourceNodeId != null) {
                        edges.put(createEdge(sourceNodeId, nodeIds.get(assignExpr), "DATA_FLOW"));
                    }
                });
            });

            b.findAll(FieldAccessExpr.class).forEach(fieldAccess -> {
                JSONObject fieldAccessNode = new JSONObject();
                fieldAccessNode.put("id", nextId.get());
                fieldAccessNode.put("type", "FIELD_ACCESS");
                fieldAccessNode.put("field", fieldAccess.getNameAsString());
                fieldAccessNode.put("scope", fieldAccess.getScope().toString());
                nodes.put(fieldAccessNode);
                nodeIds.put(fieldAccess, nextId.getAndIncrement());

                edges.put(createEdge(methodId, nodeIds.get(fieldAccess), "ACCESSES"));
            });

            b.findAll(StringLiteralExpr.class).forEach(stringLiteral -> {
                JSONObject stringNode = new JSONObject();
                stringNode.put("id", nextId.get());
                stringNode.put("type", "STRING_LITERAL");
                stringNode.put("value", stringLiteral.getValue());
                stringNode.put("length", stringLiteral.getValue().length());
                nodes.put(stringNode);
                nodeIds.put(stringLiteral, nextId.getAndIncrement());

                edges.put(createEdge(methodId, nodeIds.get(stringLiteral), "CONTAINS_LITERAL"));
            });

            b.findAll(TryStmt.class).forEach(tryStmt -> {
                JSONObject tryNode = new JSONObject();
                tryNode.put("id", nextId.get());
                tryNode.put("type", "TRY_CATCH_BLOCK");
                tryNode.put("catchClausesCount", tryStmt.getCatchClauses().size());
                tryNode.put("hasFinallyBlock", tryStmt.getFinallyBlock().isPresent());

                JSONArray exceptionTypes = new JSONArray();
                tryStmt.getCatchClauses().forEach(catchClause -> {
                    String exceptionType = catchClause.getParameter().getType().asString();
                    exceptionTypes.put(exceptionType);
                    catchClause.getBody().findAll(MethodCallExpr.class).forEach(call -> {
                        String callName = call.getNameAsString();
                        if (callName.equals("println") || callName.equals("print") ||
                            callName.equals("info") || callName.equals("debug") || 
                            callName.equals("warn") || callName.equals("warning") ||
                            callName.equals("error") || callName.equals("log") || 
                            callName.equals("printStackTrace")) {
                            boolean exposesSensitiveData = call.getArguments().stream().anyMatch(arg -> 
                                arg.toString().contains(catchClause.getParameter().getNameAsString())) ||
                                callName.equals("printStackTrace");
                            if (exposesSensitiveData) {
                                JSONObject issue = new JSONObject();
                                issue.put("catchBlockId", nodeIds.get(tryStmt));
                                issue.put("methodName", method.getNameAsString());
                                issue.put("message", "Sensitive data exposure: " + callName + " may leak exception details in catch block");
                                issue.put("severity", "Medium");
                                issue.put("suggestedFix", "Avoid logging exception details; use a generic error message instead");
                                sensitiveDataExposures.put(issue);
                            }
                        }
                    });
                });
                tryNode.put("exceptionTypes", exceptionTypes);

                nodes.put(tryNode);
                nodeIds.put(tryStmt, nextId.getAndIncrement());

                edges.put(createEdge(methodId, nodeIds.get(tryStmt), "CONTAINS_EXCEPTION_HANDLING"));

                boolean hasBroadCatch = tryStmt.getCatchClauses().stream().anyMatch(catchClause -> {
                    String exceptionType = catchClause.getParameter().getType().asString();
                    return exceptionType.equals("Exception") || exceptionType.equals("Throwable");
                });
                if (hasBroadCatch) {
                    JSONObject issue = new JSONObject();
                    issue.put("tryCatchId", nodeIds.get(tryStmt));
                    issue.put("methodName", method.getNameAsString());
                    issue.put("message", "Overly broad catch: catching Exception or Throwable");
                    issue.put("suggestedFix", "Catch specific exceptions instead of Exception or Throwable");
                    overlyBroadCatches.put(issue);
                }
            });

            b.findAll(ReturnStmt.class).forEach(returnStmt -> {
                JSONObject returnNode = new JSONObject();
                returnNode.put("id", nextId.get());
                returnNode.put("type", "RETURN_STATEMENT");
                returnStmt.getExpression().ifPresent(expr -> 
                    returnNode.put("expression", expr.toString()));
                nodes.put(returnNode);
                nodeIds.put(returnStmt, nextId.getAndIncrement());

                edges.put(createEdge(methodId, nodeIds.get(returnStmt), "CONTAINS"));
            });
        });
    }

    private static void analyzeGlobalElements(CompilationUnit cu, Map<Node, Integer> nodeIds, 
                                           JSONArray nodes, JSONArray edges, AtomicInteger nextId) {
        Integer fileId = nodeIds.get(cu);
        if (fileId == null) return;

        cu.getImports().forEach(importDecl -> {
            JSONObject importNode = new JSONObject();
            importNode.put("id", nextId.get());
            importNode.put("type", "IMPORT");
            importNode.put("name", importDecl.getNameAsString());
            importNode.put("isStatic", importDecl.isStatic());
            importNode.put("isAsterisk", importDecl.isAsterisk());
            nodes.put(importNode);
            nodeIds.put(importDecl, nextId.getAndIncrement());

            edges.put(createEdge(fileId, nodeIds.get(importDecl), "IMPORTS"));
        });

        cu.getPackageDeclaration().ifPresent(packageDecl -> {
            JSONObject packageNode = new JSONObject();
            packageNode.put("id", nextId.get());
            packageNode.put("type", "PACKAGE");
            packageNode.put("name", packageDecl.getNameAsString());
            nodes.put(packageNode);
            nodeIds.put(packageDecl, nextId.getAndIncrement());

            edges.put(createEdge(fileId, nodeIds.get(packageDecl), "BELONGS_TO"));
        });
    }

    private static JSONObject createEdge(int sourceId, int targetId, String type) {
        JSONObject edge = new JSONObject();
        edge.put("source", sourceId);
        edge.put("target", targetId);
        edge.put("type", type);
        return edge;
    }

    private static void parseArguments(String[] args) {
        for (int i = 1; i < args.length; i++) {
            switch (args[i]) {
                case "--local":
                    saveLocal = true;
                    break;
                case "--output":
                    if (i + 1 < args.length) {
                        outputPath = args[++i];
                    }
                    break;
                case "--endpoint":
                    if (i + 1 < args.length) {
                        apiEndpoint = args[++i];
                    }
                    break;
            }
        }
    }

    private static void saveGraphLocally(JSONObject graph) throws IOException {
        System.out.println("Saving code graph to: " + outputPath);
        try (java.io.FileWriter file = new java.io.FileWriter(outputPath)) {
            file.write(graph.toString(2));
        }
        System.out.println("Code graph saved successfully with " + 
                         graph.getJSONArray("nodes").length() + " nodes and " + 
                         graph.getJSONArray("edges").length() + " edges.");
    }

    private static void uploadGraph(JSONObject graph) throws IOException {
        System.out.println("Uploading code graph to: " + apiEndpoint);
        HttpURLConnection conn = (HttpURLConnection) new URL(apiEndpoint).openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setDoOutput(true);

        try (OutputStream os = conn.getOutputStream()) {
            os.write(graph.toString().getBytes());
        }

        int responseCode = conn.getResponseCode();
        if (responseCode == 200) {
            System.out.println("Upload successful - " + 
                             graph.getJSONArray("nodes").length() + " nodes and " + 
                             graph.getJSONArray("edges").length() + " edges uploaded.");
        } else {
            System.err.println("Upload failed with status: " + responseCode);
            try (java.io.InputStream errorStream = conn.getErrorStream()) {
                if (errorStream != null) {
                    System.err.println("Error details: " + new String(errorStream.readAllBytes()));
                }
            }
        }
    }
}