import com.github.javaparser.JavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.*;
import com.github.javaparser.ast.expr.*;
import com.github.javaparser.ast.stmt.*;
import com.github.javaparser.utils.SourceRoot;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

public class scanner {

    private static String apiEndpoint = "http://localhost:8080/api/scan";
    private static boolean saveLocal = false;
    private static String outputPath = "codegraph.json";

    public static void main(String[] args) throws IOException {
        if (args.length < 1) {
            System.out.println("Usage: java scanner <path-to-java-source> [--local] [--output path.json] [--endpoint url]");
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
                            Integer constructorId = nextId.getAndIncrement();
                            nodeIds.put(constructor, constructorId);

                            edges.put(createEdge(nodeIds.get(cls), constructorId, "CONTAINS"));

                            Map<String, Integer> variableToNodeId = new HashMap<>();
                            constructor.getParameters().forEach(param -> {
                                JSONObject paramNode = new JSONObject();
                                paramNode.put("id", nextId.get());
                                paramNode.put("type", "PARAMETER");
                                paramNode.put("name", param.getNameAsString());
                                paramNode.put("dataType", param.getType().asString());
                                nodes.put(paramNode);
                                Integer paramId = nextId.getAndIncrement();
                                nodeIds.put(param, paramId);
                                edges.put(createEdge(constructorId, paramId, "DECLARES"));
                                variableToNodeId.put(param.getNameAsString(), paramId);
                            });

                            analyzeMethodBody(constructor, nodeIds, nodes, edges, nextId, variableToNodeId);
                        });

                        cls.getMethods().forEach(method -> {
                            JSONObject methodNode = new JSONObject();
                            methodNode.put("id", nextId.get());
                            methodNode.put("type", "METHOD");
                            methodNode.put("name", method.getNameAsString());
                            methodNode.put("returnType", method.getType().asString());
                            methodNode.put("parameters", method.getParameters().size());
                            nodes.put(methodNode);
                            Integer methodId = nextId.getAndIncrement();
                            nodeIds.put(method, methodId);

                            edges.put(createEdge(nodeIds.get(cls), methodId, "CONTAINS"));

                            Map<String, Integer> variableToNodeId = new HashMap<>();
                            method.getParameters().forEach(param -> {
                                JSONObject paramNode = new JSONObject();
                                paramNode.put("id", nextId.get());
                                paramNode.put("type", "PARAMETER");
                                paramNode.put("name", param.getNameAsString());
                                paramNode.put("dataType", param.getType().asString());
                                nodes.put(paramNode);
                                Integer paramId = nextId.getAndIncrement();
                                nodeIds.put(param, paramId);
                                edges.put(createEdge(methodId, paramId, "DECLARES"));
                                variableToNodeId.put(param.getNameAsString(), paramId);
                            });

                            analyzeMethodBody(method, nodeIds, nodes, edges, nextId, variableToNodeId);
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
                case "METHOD_CALL":
                case "OBJECT_CREATION":
                case "TYPE_ARRAY_CALL":
                case "TYPE_CATCH_CALL": methodCalls++; break;
                case "ASSIGNMENT": assignments++; break;
                case "STRING_LITERAL": stringLiterals++; break;
                case "IF_STATEMENT":
                case "FOR_LOOP":
                case "WHILE_LOOP":
                case "FOR_EACH_LOOP":
                case "TRY_CATCH_BLOCK": controlFlows++; break;
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

        codeGraph.put("statistics", stats);

        if (saveLocal) {
            saveGraphLocally(codeGraph);
        } else {
            try {
                uploadGraph(codeGraph);
            } catch (IOException e) {
                System.err.println("Upload failed: " + e.getMessage());
                System.out.println("Saving graph locally as fallback...");
                saveGraphLocally(codeGraph);
            }
        }
    }

    private static void analyzeMethodBody(CallableDeclaration<?> method, Map<Node, Integer> nodeIds,
                                         JSONArray nodes, JSONArray edges, AtomicInteger nextId,
                                         Map<String, Integer> variableToNodeId) {
        Integer methodId = nodeIds.get(method);
        if (methodId == null) return;

        Optional<BlockStmt> body = Optional.empty();
        if (method instanceof MethodDeclaration) {
            body = ((MethodDeclaration) method).getBody();
        } else if (method instanceof ConstructorDeclaration) {
            body = Optional.of(((ConstructorDeclaration) method).getBody());
        }

        body.ifPresent(b -> {
            b.findAll(VariableDeclarator.class).forEach(varDeclarator -> {
                JSONObject varNode = new JSONObject();
                varNode.put("id", nextId.get());
                varNode.put("type", "LOCAL_VARIABLE");
                varNode.put("name", varDeclarator.getNameAsString());
                varNode.put("dataType", varDeclarator.getType().asString());

                varDeclarator.getInitializer().ifPresent(init ->
                    varNode.put("initializer", init.toString()));

                nodes.put(varNode);
                Integer varId = nextId.getAndIncrement();
                nodeIds.put(varDeclarator, varId);
                variableToNodeId.put(varDeclarator.getNameAsString(), varId);

                edges.put(createEdge(methodId, varId, "DECLARES"));

                varDeclarator.getInitializer().ifPresent(init -> {
                    init.findAll(NameExpr.class).forEach(nameExpr -> {
                        String varName = nameExpr.getNameAsString();
                        Integer sourceNodeId = variableToNodeId.get(varName);
                        if (sourceNodeId != null) {
                            edges.put(createEdge(sourceNodeId, varId, "DATA_FLOW"));
                        }
                    });
                });
            });

            b.findAll(MethodCallExpr.class).forEach(methodCall -> {
                JSONObject callNode = new JSONObject();
                callNode.put("id", nextId.get());
                callNode.put("type", "METHOD_CALL");
                callNode.put("name", methodCall.getNameAsString());
                callNode.put("arguments", methodCall.getArguments().size());
                methodCall.getScope().ifPresent(scope ->
                    callNode.put("scope", scope.toString()));
                nodes.put(callNode);
                Integer callNodeId = nextId.getAndIncrement();
                nodeIds.put(methodCall, callNodeId);

                edges.put(createEdge(methodId, callNodeId, "INVOKES"));

                methodCall.getArguments().forEach(arg -> processArgument(arg, callNodeId, variableToNodeId, edges));
            });

            b.findAll(ObjectCreationExpr.class).forEach(objCreation -> {
                JSONObject objNode = new JSONObject();
                objNode.put("id", nextId.get());
                objNode.put("type", "OBJECT_CREATION");
                objNode.put("className", objCreation.getType().asString());
                objNode.put("arguments", objCreation.getArguments().size());
                nodes.put(objNode);
                Integer objNodeId = nextId.getAndIncrement();
                nodeIds.put(objCreation, objNodeId);

                edges.put(createEdge(methodId, objNodeId, "INVOKES"));

                objCreation.getArguments().forEach(arg -> processArgument(arg, objNodeId, variableToNodeId, edges));
            });

            b.findAll(ArrayAccessExpr.class).forEach(arrayAccess -> {
                JSONObject arrayNode = new JSONObject();
                arrayNode.put("id", nextId.get());
                arrayNode.put("type", "TYPE_ARRAY_CALL");
                arrayNode.put("array", arrayAccess.getName().toString());
                arrayNode.put("index", arrayAccess.getIndex().toString());
                nodes.put(arrayNode);
                Integer arrayId = nextId.getAndIncrement();
                nodeIds.put(arrayAccess, arrayId);

                edges.put(createEdge(methodId, arrayId, "INVOKES"));

                arrayAccess.getName().findAll(NameExpr.class).forEach(name -> {
                    String varName = name.getNameAsString();
                    Integer varId = variableToNodeId.get(varName);
                    if (varId != null) {
                        edges.put(createEdge(varId, arrayId, "DATA_FLOW"));
                    }
                });
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
                    String exceptionName = catchClause.getParameter().getNameAsString();
                    JSONObject paramNode = new JSONObject();
                    paramNode.put("id", nextId.get());
                    paramNode.put("type", "TYPE_CATCH_CALL");
                    paramNode.put("name", exceptionName);
                    paramNode.put("dataType", exceptionType);
                    nodes.put(paramNode);
                    Integer paramId = nextId.getAndIncrement();
                    nodeIds.put(catchClause.getParameter(), paramId);
                    variableToNodeId.put(exceptionName, paramId);
                    edges.put(createEdge(tryNode.getInt("id"), paramId, "DECLARES"));
                    exceptionTypes.put(exceptionType);
                });
                tryNode.put("exceptionTypes", exceptionTypes);

                nodes.put(tryNode);
                Integer tryNodeId = nextId.getAndIncrement();
                nodeIds.put(tryStmt, tryNodeId);

                edges.put(createEdge(methodId, tryNodeId, "CONTAINS_EXCEPTION_HANDLING"));
            });

            b.findAll(ReturnStmt.class).forEach(returnStmt -> {
                JSONObject returnNode = new JSONObject();
                returnNode.put("id", nextId.get());
                returnNode.put("type", "RETURN_STATEMENT");
                returnStmt.getExpression().ifPresent(expr ->
                    returnNode.put("expression", expr.toString()));
                nodes.put(returnNode);
                Integer returnNodeId = nextId.getAndIncrement();
                nodeIds.put(returnStmt, returnNodeId);

                edges.put(createEdge(methodId, returnNodeId, "CONTAINS"));

                returnStmt.getExpression().ifPresent(expr ->
                    expr.findAll(NameExpr.class).forEach(nameExpr -> {
                        String varName = nameExpr.getNameAsString();
                        Integer sourceNodeId = variableToNodeId.get(varName);
                        if (sourceNodeId != null) {
                            edges.put(createEdge(sourceNodeId, returnNodeId, "DATA_FLOW"));
                        }
                    }));
            });

            b.findAll(BinaryExpr.class).forEach(binaryExpr ->
                processBinaryExpression(binaryExpr, methodId, nodes, edges, nextId, nodeIds));
            processAssignments(b, methodId, nodes, edges, nextId, nodeIds, variableToNodeId);
            processFieldAccess(b, methodId, nodes, edges, nextId, nodeIds);
            processStringLiterals(b, methodId, nodes, edges, nextId, nodeIds);
            processControlFlow(b, methodId, nodes, edges, nextId, nodeIds);
        });
    }

    private static void processBinaryExpression(Node node, Integer parentId, JSONArray nodes,
                                               JSONArray edges, AtomicInteger nextId, Map<Node, Integer> nodeIds) {
        if (node instanceof BinaryExpr) {
            BinaryExpr binaryExpr = (BinaryExpr) node;
            JSONObject exprNode = new JSONObject();
            exprNode.put("id", nextId.get());
            exprNode.put("type", "BINARY_EXPRESSION");
            exprNode.put("operator", binaryExpr.getOperator().asString());
            exprNode.put("leftOperand", binaryExpr.getLeft().toString());
            exprNode.put("rightOperand", binaryExpr.getRight().toString());
            nodes.put(exprNode);
            Integer exprId = nextId.getAndIncrement();
            nodeIds.put(binaryExpr, exprId);

            edges.put(createEdge(parentId, exprId, "CONTAINS_EXPRESSION"));

            processBinaryExpression(binaryExpr.getLeft(), exprId, nodes, edges, nextId, nodeIds);
            processBinaryExpression(binaryExpr.getRight(), exprId, nodes, edges, nextId, nodeIds);
        }
    }

    private static void processArgument(Expression arg, Integer targetNodeId, Map<String, Integer> variableToNodeId, JSONArray edges) {
        if (arg instanceof NameExpr) {
            String varName = ((NameExpr) arg).getNameAsString();
            Integer varNodeId = variableToNodeId.get(varName);
            if (varNodeId != null) {
                edges.put(createEdge(varNodeId, targetNodeId, "DATA_FLOW"));
            }
        } else if (arg instanceof BinaryExpr) {
            BinaryExpr binaryExpr = (BinaryExpr) arg;
            binaryExpr.findAll(NameExpr.class).forEach(nameExpr -> {
                String varName = nameExpr.getNameAsString();
                Integer varNodeId = variableToNodeId.get(varName);
                if (varNodeId != null) {
                    edges.put(createEdge(varNodeId, targetNodeId, "DATA_FLOW"));
                }
            });
        } else if (arg instanceof MethodCallExpr) {
            MethodCallExpr nestedCall = (MethodCallExpr) arg;
            nestedCall.getScope().ifPresent(scope -> {
                if (scope instanceof NameExpr) {
                    String scopeName = ((NameExpr) scope).getNameAsString();
                    Integer scopeNodeId = variableToNodeId.get(scopeName);
                    if (scopeNodeId != null) {
                        edges.put(createEdge(scopeNodeId, targetNodeId, "DATA_FLOW"));
                    }
                }
            });
            nestedCall.getArguments().forEach(nestedArg -> processArgument(nestedArg, targetNodeId, variableToNodeId, edges));
        } else if (arg instanceof ObjectCreationExpr) {
            ObjectCreationExpr nestedCreation = (ObjectCreationExpr) arg;
            nestedCreation.getArguments().forEach(nestedArg -> processArgument(nestedArg, targetNodeId, variableToNodeId, edges));
        }
    }

    private static void processControlFlow(BlockStmt body, Integer methodId, JSONArray nodes,
                                          JSONArray edges, AtomicInteger nextId, Map<Node, Integer> nodeIds) {
        body.findAll(IfStmt.class).forEach(ifStmt -> {
            JSONObject ifNode = new JSONObject();
            ifNode.put("id", nextId.get());
            ifNode.put("type", "IF_STATEMENT");
            ifNode.put("condition", ifStmt.getCondition().toString());
            ifNode.put("hasElse", ifStmt.getElseStmt().isPresent());
            nodes.put(ifNode);
            nodeIds.put(ifStmt, nextId.getAndIncrement());

            edges.put(createEdge(methodId, nodeIds.get(ifStmt), "CONTAINS_CONTROL_FLOW"));
        });

        body.findAll(ForStmt.class).forEach(forStmt -> {
            JSONObject forNode = new JSONObject();
            forNode.put("id", nextId.get());
            forNode.put("type", "FOR_LOOP");
            forStmt.getCompare().ifPresent(compare ->
                forNode.put("condition", compare.toString()));
            nodes.put(forNode);
            Integer forId = nextId.getAndIncrement();
            nodeIds.put(forStmt, forId);

            edges.put(createEdge(methodId, forId, "CONTAINS_CONTROL_FLOW"));
        });

        body.findAll(WhileStmt.class).forEach(whileStmt -> {
            JSONObject whileNode = new JSONObject();
            whileNode.put("id", nextId.get());
            whileNode.put("type", "WHILE_LOOP");
            whileNode.put("condition", whileStmt.getCondition().toString());
            nodes.put(whileNode);
            Integer whileId = nextId.getAndIncrement();
            nodeIds.put(whileStmt, whileId);

            edges.put(createEdge(methodId, whileId, "CONTAINS_CONTROL_FLOW"));
        });

        body.findAll(ForEachStmt.class).forEach(f -> {
            JSONObject forEachNode = new JSONObject();
            forEachNode.put("id", nextId.get());
            forEachNode.put("type", "FOR_EACH_LOOP");
            forEachNode.put("variable", f.getVariable().toString());
            forEachNode.put("iterable", f.getIterable().toString());
            nodes.put(forEachNode);
            Integer forEachId = nextId.getAndIncrement();
            nodeIds.put(f, forEachId);

            edges.put(createEdge(methodId, forEachId, "CONTAINS_CONTROL_FLOW"));
        });
    }

    private static void processAssignments(BlockStmt body, Integer methodId, JSONArray nodes,
                                         JSONArray edges, AtomicInteger nextId, Map<Node, Integer> nodeIds,
                                         Map<String, Integer> variableToNodeId) {
        body.findAll(AssignExpr.class).forEach(assignExpr -> {
            JSONObject assignNode = new JSONObject();
            assignNode.put("id", nextId.get());
            assignNode.put("type", "ASSIGNMENT");
            assignNode.put("target", assignExpr.getTarget().toString());
            assignNode.put("value", assignExpr.getValue().toString());
            assignNode.put("operator", assignExpr.getOperator().toString());
            nodes.put(assignNode);
            Integer assignId = nextId.getAndIncrement();
            nodeIds.put(assignExpr, assignId);

            edges.put(createEdge(assignId, methodId, "CONTAINS_ASSIGNMENT"));

            assignExpr.getValue().findAll(NameExpr.class).forEach(nameExpr -> {
                String varName = nameExpr.getNameAsString();
                Integer sourceNodeId = variableToNodeId.get(varName);
                if (sourceNodeId != null) {
                    edges.put(createEdge(sourceNodeId, assignId, "DATA_FLOW"));
                }
            });
        });
    }

    private static void processFieldAccess(BlockStmt body, Integer methodId, JSONArray nodes,
                                          JSONArray edges, AtomicInteger nextId, Map<Node, Integer> nodeIds) {
        body.findAll(FieldAccessExpr.class).forEach(fieldAccess -> {
            JSONObject fieldAccessNode = new JSONObject();
            fieldAccessNode.put("id", nextId.get());
            fieldAccessNode.put("type", "FIELD_ACCESS");
            fieldAccessNode.put("field", fieldAccess.getNameAsString());
            fieldAccessNode.put("scope", fieldAccess.getScope().toString());
            nodes.put(fieldAccessNode);
            nodeIds.put(fieldAccess, nextId.getAndIncrement());

            edges.put(createEdge(methodId, nodeIds.get(fieldAccess), "ACCESSES"));
        });
    }

    private static void processStringLiterals(BlockStmt body, Integer methodId, JSONArray nodes,
                                            JSONArray edges, AtomicInteger nextId, Map<Node, Integer> nodeIds) {
        body.findAll(StringLiteralExpr.class).forEach(stringLiteral -> {
            JSONObject stringNode = new JSONObject();
            stringNode.put("id", nextId.get());
            stringNode.put("type", "STRING_LITERAL");
            stringNode.put("value", stringLiteral.getValue());
            stringNode.put("length", stringLiteral.getValue().length());
            nodes.put(stringNode);
            nodeIds.put(stringLiteral, nextId.getAndIncrement());

            edges.put(createEdge(methodId, nodeIds.get(stringLiteral), "CONTAINS_LITERAL"));
        });
    }

    private static void analyzeGlobalElements(CompilationUnit cu, Map<Node, Integer> nodeIds,
                                             JSONArray nodes, JSONArray edges, AtomicInteger nextId) {
        cu.getPackageDeclaration().ifPresent(pd -> {
            JSONObject packageNode = new JSONObject();
            packageNode.put("id", nextId.get());
            packageNode.put("type", "PACKAGE");
            packageNode.put("name", pd.getNameAsString());
            nodes.put(packageNode);
            nodeIds.put(pd, nextId.getAndIncrement());

            edges.put(createEdge(nodeIds.get(cu), nodeIds.get(pd), "BELONGS_TO"));
        });

        cu.getImports().forEach(im -> {
            JSONObject importNode = new JSONObject();
            importNode.put("id", nextId.get());
            importNode.put("type", "IMPORT");
            importNode.put("name", im.getNameAsString());
            importNode.put("isStatic", im.isStatic());
            importNode.put("isAsterisk", im.isAsterisk());
            importNode.put("id", nextId.get());
            nodes.put(importNode);
            nodeIds.put(im, nextId.getAndIncrement());

            edges.put(createEdge(nodeIds.get(cu), nodeIds.get(im), "IMPORTS"));
        });
    }

    private static JSONObject createEdge(int source, int target, String type) {
        JSONObject edge = new JSONObject();
        edge.put("source", source);
        edge.put("target", target);
        edge.put("type", type);
        return edge;
    }

    private static void parseArguments(String[] args) {
        for (int i = 1; i < args.length; i++) {
            if (args[i].equals("--local")) {
                saveLocal = true;
            } else if (args[i].equals("--output") && i + 1 < args.length) {
                outputPath = args[++i];
            } else if (args[i].equals("--endpoint") && i + 1 < args.length) {
                apiEndpoint = args[++i];
            }
        }
    }

    private static void saveGraphLocally(JSONObject codeGraph) throws IOException {
        File outputFile = new File(outputPath);
        outputFile.getParentFile().mkdirs(); // Ensure parent directories exist
        try (FileWriter file = new FileWriter(outputFile)) {
            file.write(codeGraph.toString(2));
            System.out.println("Code graph saved to: " + outputPath);
        }
    }

    private static void uploadGraph(JSONObject codeGraph) throws IOException {
        String scanId = codeGraph.getString("scanId");
        URL url = new URL(apiEndpoint);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setRequestProperty("Authorization", "Basic " +
            Base64.getEncoder().encodeToString("user:secret".getBytes()));
        conn.setDoOutput(true);

        try (OutputStream os = conn.getOutputStream()) {
            byte[] input = codeGraph.toString().getBytes("utf-8");
            os.write(input, 0, input.length);
        }

        int responseCode = conn.getResponseCode();
        if (responseCode == HttpURLConnection.HTTP_OK) {
            System.out.println("Code graph uploaded successfully to: " + apiEndpoint + " with scanId: " + scanId);
        } else {
            throw new IOException("Failed to upload code graph: HTTP error code " + responseCode);
        }
    }
}