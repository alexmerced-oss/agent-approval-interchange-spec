package io.github.alexmercedcoder.aais;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.UUID;
import java.util.Set;
import java.util.regex.Pattern;
import org.erdtman.jcs.JsonCanonicalizer;

/** AAIS parsing, canonical action binding, and Core validation. */
public final class Aais {
  /** Supported AAIS document-model version. */
  public static final String VERSION = "1.0";
  /** Shared JSON mapper used by builders and integrations. */
  public static final ObjectMapper JSON = new ObjectMapper();
  private static final Pattern ID = Pattern.compile("^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$");
  private static final Pattern DIGEST = Pattern.compile("^sha256:[0-9a-f]{64}$");
  private static final Set<String> TOP_LEVEL = Set.of("aais", "type", "id", "occurred_at", "sequence", "stream", "extensions", "request", "decision", "resolution", "snapshot", "activity");
  private Aais() {}

  /** Parse one JSON envelope and reject malformed or unknown top-level fields.
   * @param json serialized AAIS envelope
   * @return validated defensive copy
   */
  public static ObjectNode parse(String json) {
    try {
      JsonNode value = JSON.readTree(json);
      if (!(value instanceof ObjectNode object)) throw new AaisException("AAIS document must be an object");
      Iterator<String> names = object.fieldNames(); while (names.hasNext()) { String name = names.next(); if (!TOP_LEVEL.contains(name)) throw new AaisException("unknown top-level field: " + name); }
      validate(object); return object.deepCopy();
    } catch (JsonProcessingException error) { throw new AaisException("invalid JSON", error); }
  }

  /** Compute the RFC 8785 / SHA-256 action binding.
   * @param action exact action object
   * @return lowercase {@code sha256:} binding
   */
  public static String actionDigest(JsonNode action) {
    try {
      byte[] canonical = new JsonCanonicalizer(action.toString()).getEncodedUTF8();
      return "sha256:" + HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(canonical));
    } catch (IOException | NoSuchAlgorithmException error) { throw new AaisException("cannot canonicalize action", error); }
  }

  /** Build and validate an approval.requested envelope.
   * @param action exact proposed action
   * @param origin execution provenance
   * @param risk display-safe risk assessment
   * @param choices authority-offered choices
   * @param sequence stream sequence
   * @param stream optional stream identifier
   * @param createdAt creation time, or null for now
   * @param expiresAt optional expiry
   * @return validated request envelope
   */
  public static ObjectNode createRequest(ObjectNode action,ObjectNode origin,ObjectNode risk,ArrayNode choices,long sequence,String stream,OffsetDateTime createdAt,OffsetDateTime expiresAt){OffsetDateTime created=createdAt==null?OffsetDateTime.now():createdAt;String at=created.toString();ObjectNode request=JSON.createObjectNode().put("id",id("apr")).put("created_at",at).put("status","pending").put("action_digest",actionDigest(action));request.set("origin",origin.deepCopy());request.set("action",action.deepCopy());request.set("risk",risk.deepCopy());request.set("choices",choices.deepCopy());if(expiresAt!=null)request.put("expires_at",expiresAt.toString());ObjectNode envelope=JSON.createObjectNode().put("aais","1.0").put("type","approval.requested").put("id",id("evt")).put("occurred_at",at).put("sequence",sequence);if(stream!=null)envelope.put("stream",stream);envelope.set("request",request);validate(envelope);return envelope;}

  /** Build a decision bound to an approval.requested envelope.
   * @param requested validated requested envelope
   * @param decision approve, deny, or cancel
   * @param scope once, session, or persistent
   * @param actor authenticated actor claim
   * @param sequence stream sequence
   * @param decidedAt decision time, or null for now
   * @return validated decision envelope
   */
  public static ObjectNode createDecision(ObjectNode requested,String decision,String scope,ObjectNode actor,long sequence,OffsetDateTime decidedAt){validate(requested);if(!"approval.requested".equals(requested.path("type").asText()))throw new AaisException("createDecision requires approval.requested");String at=(decidedAt==null?OffsetDateTime.now():decidedAt).toString();ObjectNode body=JSON.createObjectNode().put("id",id("dec")).put("request_id",requested.path("request").path("id").asText()).put("action_digest",requested.path("request").path("action_digest").asText()).put("decided_at",at).put("decision",decision).put("scope",scope);body.set("actor",actor.deepCopy());ObjectNode envelope=JSON.createObjectNode().put("aais","1.0").put("type","approval.decided").put("id",id("evt")).put("occurred_at",at).put("sequence",sequence);envelope.set("decision",body);validate(envelope);return envelope;}

  /** Validate one AAIS 1.0 envelope.
   * @param envelope envelope to validate
   */
  public static void validate(ObjectNode envelope) {
    requireText(envelope, "aais"); if (!VERSION.equals(envelope.path("aais").asText())) fail("aais must equal 1.0");
    requireId(envelope, "id"); requireTime(envelope, "occurred_at"); if (!envelope.path("sequence").canConvertToLong() || envelope.path("sequence").asLong() < 0) fail("sequence must be non-negative");
    String type = requireText(envelope, "type"); int payloads = count(envelope,"request","decision","resolution","snapshot","activity"); if (payloads != 1) fail("exactly one event payload is required");
    switch (type) {
      case "approval.requested" -> validateRequest(requireObject(envelope,"request"));
      case "approval.decided" -> validateDecision(requireObject(envelope,"decision"));
      case "approval.resolved" -> validateResolution(requireObject(envelope,"resolution"));
      case "approval.snapshot" -> { ObjectNode snapshot=requireObject(envelope,"snapshot"); if (!snapshot.path("as_of_sequence").canConvertToLong() || !snapshot.path("pending").isArray()) fail("invalid snapshot"); snapshot.path("pending").forEach(item -> { if (!item.isObject()) fail("pending request must be an object"); validateRequest((ObjectNode)item); }); }
      case "approval.activity" -> { ObjectNode activity=requireObject(envelope,"activity"); requireId(activity,"request_id"); requireText(activity,"message"); }
      default -> fail("unknown event type");
    }
  }

  private static void validateRequest(ObjectNode request) {
    requireId(request,"id"); if (!"pending".equals(requireText(request,"status"))) fail("request status must be pending"); OffsetDateTime created=time(requireText(request,"created_at")); if(request.has("expires_at")&&!time(requireText(request,"expires_at")).isAfter(created))fail("expires_at must be later than created_at");
    ObjectNode origin=requireObject(request,"origin");requireId(origin,"harness");requireId(origin,"session_id");ObjectNode action=requireObject(request,"action");requireId(action,"kind");requireId(action,"name");requireText(action,"summary");requireObject(action,"arguments");
    if(action.path("presentation").path("redacted").asBoolean(false)&&action.path("presentation").path("binding_hint").asText("").isBlank())fail("redacted action requires binding_hint");String digest=requireText(request,"action_digest");if(!DIGEST.matcher(digest).matches()||!digest.equals(actionDigest(action)))fail("action_digest does not match action");
    ObjectNode risk=requireObject(request,"risk");if(!Set.of("low","medium","high","critical").contains(requireText(risk,"level"))||!risk.path("reasons").isArray()||risk.path("reasons").isEmpty())fail("invalid risk");JsonNode choices=request.path("choices");if(!choices.isArray()||choices.isEmpty())fail("choices must be non-empty");boolean exit=false;Set<String> seen=new java.util.HashSet<>();for(JsonNode choice:choices){if(choice.has("allow_edits"))fail("allow_edits is not part of AAIS 1.0");String decision=requireText(choice,"decision"),scope=requireText(choice,"scope");requireText(choice,"label");if(!Set.of("approve","deny","cancel").contains(decision)||!Set.of("once","session","persistent").contains(scope))fail("invalid choice");if(!seen.add(decision+"\u0000"+scope))fail("decision and scope tuples must be unique");if(!"approve".equals(decision)){exit=true;if(!"once".equals(scope))fail("deny/cancel choice invalid");}if(!"once".equals(scope)&&(!choice.path("scope_constraints").isObject()||choice.path("scope_constraints").isEmpty()))fail("broader scope requires constraints");}if(!exit)fail("at least one deny or cancel choice is required");
  }
  private static void validateDecision(ObjectNode decision){if(decision.has("replacement_arguments"))fail("replacement_arguments is not part of AAIS 1.0");requireId(decision,"id");requireId(decision,"request_id");if(!DIGEST.matcher(requireText(decision,"action_digest")).matches())fail("invalid digest");requireTime(decision,"decided_at");String value=requireText(decision,"decision"),scope=requireText(decision,"scope");if(!Set.of("approve","deny","cancel").contains(value)||!Set.of("once","session","persistent").contains(scope))fail("invalid decision");ObjectNode actor=requireObject(decision,"actor");requireId(actor,"id");if(!Set.of("human","policy").contains(requireText(actor,"type")))fail("invalid actor");if(!"approve".equals(value)&&!"once".equals(scope))fail("deny/cancel decision invalid");}
  private static void validateResolution(ObjectNode resolution){requireId(resolution,"id");requireId(resolution,"request_id");if(!DIGEST.matcher(requireText(resolution,"action_digest")).matches())fail("invalid digest");requireTime(resolution,"resolved_at");if(!Set.of("approved","denied","cancelled","expired","stale","conflict","invalid").contains(requireText(resolution,"outcome")))fail("invalid outcome");requireText(resolution,"message");}
  static OffsetDateTime time(String value){try{return OffsetDateTime.parse(value);}catch(DateTimeParseException error){throw new AaisException("invalid RFC 3339 timestamp",error);}}
  static String requireText(JsonNode node,String field){String value=node.path(field).asText("");if(value.isBlank())fail(field+" must be non-empty");return value;}
  static void requireTime(JsonNode node,String field){time(requireText(node,field));}
  static void requireId(JsonNode node,String field){if(!ID.matcher(requireText(node,field)).matches())fail("invalid "+field);}
  static ObjectNode requireObject(JsonNode node,String field){JsonNode value=node.path(field);if(!(value instanceof ObjectNode object))throw new AaisException(field+" must be an object");return object;}
  static void fail(String message){throw new AaisException(message);}
  private static String id(String prefix){return prefix+"_"+UUID.randomUUID().toString().replace("-","");}
  private static int count(JsonNode node,String...fields){int total=0;for(String field:fields)if(node.has(field))total++;return total;}
}
