import { 
  analysisJobs, 
  uploadedFiles, 
  vulnerabilities,
  type AnalysisJob, 
  type InsertAnalysisJob,
  type UploadedFile,
  type InsertUploadedFile,
  type Vulnerability,
  type InsertVulnerability
} from "@shared/schema";

export interface IStorage {
  // Analysis Jobs
  createAnalysisJob(job: InsertAnalysisJob): Promise<AnalysisJob>;
  getAnalysisJob(id: number): Promise<AnalysisJob | undefined>;
  updateAnalysisJob(id: number, updates: Partial<AnalysisJob>): Promise<AnalysisJob>;
  
  // Uploaded Files
  createUploadedFile(file: InsertUploadedFile): Promise<UploadedFile>;
  getFilesByJobId(jobId: number): Promise<UploadedFile[]>;
  deleteFilesByJobId(jobId: number): Promise<void>;
  
  // Vulnerabilities
  createVulnerability(vulnerability: InsertVulnerability): Promise<Vulnerability>;
  getVulnerabilitiesByJobId(jobId: number): Promise<Vulnerability[]>;
  deleteVulnerabilitiesByJobId(jobId: number): Promise<void>;
  
  // Cleanup
  deleteJobAndRelatedData(jobId: number): Promise<void>;
}

export class MemStorage implements IStorage {
  private analysisJobs: Map<number, AnalysisJob>;
  private uploadedFiles: Map<number, UploadedFile>;
  private vulnerabilities: Map<number, Vulnerability>;
  private currentJobId: number;
  private currentFileId: number;
  private currentVulnId: number;

  constructor() {
    this.analysisJobs = new Map();
    this.uploadedFiles = new Map();
    this.vulnerabilities = new Map();
    this.currentJobId = 1;
    this.currentFileId = 1;
    this.currentVulnId = 1;
  }

  async createAnalysisJob(insertJob: InsertAnalysisJob): Promise<AnalysisJob> {
    const id = this.currentJobId++;
    const job: AnalysisJob = {
      ...insertJob,
      id,
      createdAt: new Date(),
      completedAt: null,
    };
    this.analysisJobs.set(id, job);
    return job;
  }

  async getAnalysisJob(id: number): Promise<AnalysisJob | undefined> {
    return this.analysisJobs.get(id);
  }

  async updateAnalysisJob(id: number, updates: Partial<AnalysisJob>): Promise<AnalysisJob> {
    const existing = this.analysisJobs.get(id);
    if (!existing) {
      throw new Error(`Analysis job ${id} not found`);
    }
    const updated = { ...existing, ...updates };
    this.analysisJobs.set(id, updated);
    return updated;
  }

  async createUploadedFile(insertFile: InsertUploadedFile): Promise<UploadedFile> {
    const id = this.currentFileId++;
    const file: UploadedFile = {
      ...insertFile,
      id,
      createdAt: new Date(),
    };
    this.uploadedFiles.set(id, file);
    return file;
  }

  async getFilesByJobId(jobId: number): Promise<UploadedFile[]> {
    return Array.from(this.uploadedFiles.values()).filter(file => file.jobId === jobId);
  }

  async deleteFilesByJobId(jobId: number): Promise<void> {
    const toDelete = Array.from(this.uploadedFiles.keys()).filter(id => 
      this.uploadedFiles.get(id)?.jobId === jobId
    );
    toDelete.forEach(id => this.uploadedFiles.delete(id));
  }

  async createVulnerability(insertVuln: InsertVulnerability): Promise<Vulnerability> {
    const id = this.currentVulnId++;
    const vulnerability: Vulnerability = {
      ...insertVuln,
      id,
      createdAt: new Date(),
    };
    this.vulnerabilities.set(id, vulnerability);
    return vulnerability;
  }

  async getVulnerabilitiesByJobId(jobId: number): Promise<Vulnerability[]> {
    return Array.from(this.vulnerabilities.values()).filter(vuln => vuln.jobId === jobId);
  }

  async deleteVulnerabilitiesByJobId(jobId: number): Promise<void> {
    const toDelete = Array.from(this.vulnerabilities.keys()).filter(id => 
      this.vulnerabilities.get(id)?.jobId === jobId
    );
    toDelete.forEach(id => this.vulnerabilities.delete(id));
  }

  async deleteJobAndRelatedData(jobId: number): Promise<void> {
    await this.deleteFilesByJobId(jobId);
    await this.deleteVulnerabilitiesByJobId(jobId);
    this.analysisJobs.delete(jobId);
  }
}

export const storage = new MemStorage();
