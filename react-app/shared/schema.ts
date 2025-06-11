import { pgTable, text, serial, integer, timestamp, jsonb } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

export const analysisJobs = pgTable("analysis_jobs", {
  id: serial("id").primaryKey(),
  status: text("status").notNull().default("pending"), // pending, processing, completed, failed
  totalFiles: integer("total_files").notNull().default(0),
  processedFiles: integer("processed_files").notNull().default(0),
  vulnerabilities: jsonb("vulnerabilities").notNull().default([]),
  createdAt: timestamp("created_at").notNull().defaultNow(),
  completedAt: timestamp("completed_at"),
});

export const uploadedFiles = pgTable("uploaded_files", {
  id: serial("id").primaryKey(),
  jobId: integer("job_id").notNull(),
  filename: text("filename").notNull(),
  language: text("language").notNull(),
  content: text("content").notNull(),
  size: integer("size").notNull(),
  createdAt: timestamp("created_at").notNull().defaultNow(),
});

export const vulnerabilities = pgTable("vulnerabilities", {
  id: serial("id").primaryKey(),
  jobId: integer("job_id").notNull(),
  fileId: integer("file_id").notNull(),
  ruleId: text("rule_id").notNull(),
  severity: text("severity").notNull(), // critical, high, medium, low
  title: text("title").notNull(),
  description: text("description").notNull(),
  category: text("category").notNull(),
  line: integer("line").notNull(),
  column: integer("column"),
  code: text("code"),
  recommendation: text("recommendation"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
});

export const insertAnalysisJobSchema = createInsertSchema(analysisJobs).omit({
  id: true,
  createdAt: true,
  completedAt: true,
});

export const insertUploadedFileSchema = createInsertSchema(uploadedFiles).omit({
  id: true,
  createdAt: true,
});

export const insertVulnerabilitySchema = createInsertSchema(vulnerabilities).omit({
  id: true,
  createdAt: true,
});

export type AnalysisJob = typeof analysisJobs.$inferSelect;
export type InsertAnalysisJob = z.infer<typeof insertAnalysisJobSchema>;
export type UploadedFile = typeof uploadedFiles.$inferSelect;
export type InsertUploadedFile = z.infer<typeof insertUploadedFileSchema>;
export type Vulnerability = typeof vulnerabilities.$inferSelect;
export type InsertVulnerability = z.infer<typeof insertVulnerabilitySchema>;

// Frontend types
export interface FileUpload {
  id: string;
  file: File;
  language: string;
  progress: number;
}

export interface AnalysisProgress {
  step: number;
  percentage: number;
  message: string;
  currentFile?: string;
}

export interface SecurityReport {
  jobId: number;
  totalVulnerabilities: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  filesAnalyzed: number;
  linesOfCode: number;
  rulesApplied: number;
  analysisTime: string;
  vulnerabilities: Vulnerability[];
  cfg?: ControlFlowGraph;
  dfg?: DataFlowGraph;
}

export interface GraphNode {
  id: string;
  type: string;
  label: string;
  line?: number;
  column?: number;
  code?: string;
  metadata?: Record<string, any>;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  type: string;
  label?: string;
  metadata?: Record<string, any>;
}

export interface ControlFlowGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
  entry: string;
  exit: string;
  metadata: {
    language: string;
    filename: string;
    generatedAt: string;
  };
}

export interface DataFlowGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
  variables: Map<string, VariableInfo>;
  metadata: {
    language: string;
    filename: string;
    generatedAt: string;
  };
}

export interface VariableInfo {
  name: string;
  type?: string;
  definitionSites: string[];
  useSites: string[];
  scope: string;
}

export interface OwaspRule {
  id: string;
  name: string;
  description: string;
  category: string;
  severity: string;
  pattern: string | RegExp;
  recommendation: string;
  enabled: boolean;
}
