import { createHash, randomUUID } from "node:crypto";
import Ajv2020, { type ErrorObject } from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import canonicalize from "canonicalize";
import schema from "../../schema/v1/aais-1.0.schema.json";

export type JsonObject = Record<string, unknown>;
export type DecisionValue = "approve" | "deny" | "cancel";
export type Scope = "once" | "session" | "persistent";

export class ApprovalError extends Error {}
export class ValidationError extends ApprovalError {}
export class ConflictError extends ApprovalError {}

const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false });
addFormats(ajv);
const schemaValidator = ajv.compile(schema);

function clone<T>(value: T): T {
  return structuredClone(value);
}

function errorMessage(errors: ErrorObject[] | null | undefined): string {
  const error = errors?.[0];
  return error ? `${error.instancePath || "/"}: ${error.message ?? "invalid"}` : "invalid AAIS document";
}

export function actionDigest(action: JsonObject): string {
  const encoded = canonicalize(action);
  if (encoded === undefined) throw new ValidationError("action is not canonicalizable JSON");
  return `sha256:${createHash("sha256").update(encoded, "utf8").digest("hex")}`;
}

function parseTime(value: unknown): number {
  if (typeof value !== "string" || !/(Z|[+-]\d\d:\d\d)$/.test(value)) {
    throw new ValidationError("timestamps must have an explicit UTC offset");
  }
  const parsed = Date.parse(value);
  if (Number.isNaN(parsed)) throw new ValidationError(`invalid RFC 3339 timestamp: ${value}`);
  return parsed;
}

export function validate(document: unknown): JsonObject {
  const candidate = clone(document) as JsonObject;
  if (!schemaValidator(candidate)) throw new ValidationError(errorMessage(schemaValidator.errors));
  if (candidate.type === "approval.requested") {
    const request = candidate.request as JsonObject;
    const choices = request.choices as JsonObject[];
    if (!choices.some((choice) => choice.decision === "deny" || choice.decision === "cancel")) {
      throw new ValidationError("/request/choices: at least one deny or cancel choice is required");
    }
    const tuples = choices.map((choice) => `${String(choice.decision)}\u0000${String(choice.scope)}`);
    if (new Set(tuples).size !== tuples.length) {
      throw new ValidationError("/request/choices: decision and scope tuples must be unique");
    }
    if (request.action_digest !== actionDigest(request.action as JsonObject)) {
      throw new ValidationError("/request/action_digest: does not match the canonical action");
    }
    if (request.expires_at && parseTime(request.expires_at) <= parseTime(request.created_at)) {
      throw new ValidationError("/request/expires_at: must be later than created_at");
    }
  }
  return candidate;
}

const id = (prefix: string): string => `${prefix}_${randomUUID().replaceAll("-", "")}`;
const now = (): string => new Date().toISOString();

export interface CreateRequestOptions {
  action: JsonObject;
  origin: JsonObject;
  risk: JsonObject;
  choices: JsonObject[];
  sequence: number;
  stream?: string;
  requestId?: string;
  eventId?: string;
  createdAt?: string;
  expiresAt?: string;
}

export function createRequest(options: CreateRequestOptions): JsonObject {
  const createdAt = options.createdAt ?? now();
  const request: JsonObject = {
    id: options.requestId ?? id("apr"), created_at: createdAt, status: "pending",
    origin: options.origin, action: options.action, action_digest: actionDigest(options.action),
    risk: options.risk, choices: options.choices,
  };
  if (options.expiresAt) request.expires_at = options.expiresAt;
  const envelope: JsonObject = {
    aais: "1.0", type: "approval.requested", id: options.eventId ?? id("evt"),
    occurred_at: createdAt, sequence: options.sequence, request,
  };
  if (options.stream) envelope.stream = options.stream;
  return validate(envelope);
}

export interface CreateDecisionOptions {
  decision: DecisionValue;
  scope: Scope;
  actor: JsonObject;
  sequence: number;
  stream?: string;
  decisionId?: string;
  eventId?: string;
  decidedAt?: string;
}

export function createDecision(requestedDocument: JsonObject, options: CreateDecisionOptions): JsonObject {
  const requested = validate(requestedDocument);
  if (requested.type !== "approval.requested") throw new ValidationError("createDecision requires approval.requested");
  const request = requested.request as JsonObject;
  const decidedAt = options.decidedAt ?? now();
  const decision: JsonObject = {
    id: options.decisionId ?? id("dec"), request_id: request.id,
    action_digest: request.action_digest, decided_at: decidedAt,
    decision: options.decision, scope: options.scope, actor: options.actor,
  };
  const envelope: JsonObject = {
    aais: "1.0", type: "approval.decided", id: options.eventId ?? id("evt"),
    occurred_at: decidedAt, sequence: options.sequence, decision,
  };
  if (options.stream) envelope.stream = options.stream;
  return validate(envelope);
}

export class ApprovalStore {
  private readonly pending = new Map<string, JsonObject>();
  private readonly resolutions = new Map<string, JsonObject>();
  private readonly fingerprints = new Map<string, string>();
  public lastSequence = 0;

  add(document: JsonObject): JsonObject {
    const envelope = validate(document);
    if (envelope.type !== "approval.requested") throw new ValidationError("store.add requires approval.requested");
    const requestId = (envelope.request as JsonObject).id as string;
    const existing = this.pending.get(requestId);
    if (existing && canonicalize(existing) !== canonicalize(envelope)) {
      throw new ConflictError(`request ${requestId} already exists with different content`);
    }
    this.pending.set(requestId, envelope);
    this.lastSequence = Math.max(this.lastSequence, envelope.sequence as number);
    return clone(envelope);
  }

  decide(document: JsonObject, options: { now?: Date; currentAction?: JsonObject; sequence?: number } = {}): JsonObject {
    const envelope = validate(document);
    if (envelope.type !== "approval.decided") throw new ValidationError("store.decide requires approval.decided");
    const decision = envelope.decision as JsonObject;
    const requestId = decision.request_id as string;
    const fingerprint = actionDigest(decision);
    const prior = this.resolutions.get(requestId);
    if (prior) {
      if (this.fingerprints.get(requestId) === fingerprint) return clone(prior);
      throw new ConflictError(`request ${requestId} was already resolved`);
    }
    const requested = this.pending.get(requestId);
    if (!requested) throw new ValidationError(`unknown pending request: ${requestId}`);
    const request = requested.request as JsonObject;
    const instant = options.now ?? new Date();
    let outcome = decision.decision === "approve" ? "approved" : decision.decision === "deny" ? "denied" : "cancelled";
    let message = outcome === "approved" ? "Approval accepted." : outcome === "denied" ? "Action denied." : "Approval cancelled.";
    if (request.expires_at && instant.getTime() >= parseTime(request.expires_at)) {
      outcome = "expired"; message = "Approval request expired.";
    } else if (decision.action_digest !== request.action_digest ||
      (options.currentAction && actionDigest(options.currentAction) !== request.action_digest)) {
      outcome = "stale"; message = "The decision does not match the current action.";
    } else {
      const offered = (request.choices as JsonObject[]).find(
        (choice) => choice.decision === decision.decision && choice.scope === decision.scope,
      );
      if (!offered) { outcome = "invalid"; message = "The selected decision and scope were not offered."; }
    }
    const resolvedAt = instant.toISOString();
    const resolution: JsonObject = {
      id: id("res"), request_id: requestId, decision_id: decision.id,
      action_digest: request.action_digest, resolved_at: resolvedAt, outcome, message,
    };
    if (outcome === "approved" || outcome === "denied") resolution.effective_scope = decision.scope;
    const result: JsonObject = {
      aais: "1.0", type: "approval.resolved", id: id("evt"), occurred_at: resolvedAt,
      sequence: options.sequence ?? Math.max(this.lastSequence + 1, envelope.sequence as number), resolution,
    };
    if (requested.stream) result.stream = requested.stream;
    const valid = validate(result);
    this.pending.delete(requestId);
    this.resolutions.set(requestId, valid);
    this.fingerprints.set(requestId, fingerprint);
    this.lastSequence = Math.max(this.lastSequence, valid.sequence as number);
    return clone(valid);
  }

  snapshot(stream?: string, instant: Date = new Date()): JsonObject {
    const pending = [...this.pending.values()]
      .filter((item) => {
        const request = item.request as JsonObject;
        return !request.expires_at || instant.getTime() < parseTime(request.expires_at);
      })
      .map((item) => clone(item.request));
    const envelope: JsonObject = {
      aais: "1.0", type: "approval.snapshot", id: id("evt"), occurred_at: instant.toISOString(),
      sequence: this.lastSequence,
      snapshot: { as_of_sequence: this.lastSequence, pending },
    };
    if (stream) envelope.stream = stream;
    return validate(envelope);
  }

  static fromSnapshot(document: JsonObject): ApprovalStore {
    const snapshot = validate(document);
    if (snapshot.type !== "approval.snapshot") throw new ValidationError("fromSnapshot requires approval.snapshot");
    const body = snapshot.snapshot as JsonObject;
    const store = new ApprovalStore();
    store.lastSequence = body.as_of_sequence as number;
    for (const request of body.pending as JsonObject[]) {
      const wrapper: JsonObject = {
        aais: "1.0", type: "approval.requested", id: `restore_${request.id}`,
        occurred_at: request.created_at, sequence: store.lastSequence, request,
      };
      if (snapshot.stream) wrapper.stream = snapshot.stream;
      store.add(wrapper);
    }
    return store;
  }
}
