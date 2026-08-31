package io.github.alexmercedcoder.aais;

import static org.junit.jupiter.api.Assertions.*;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.OffsetDateTime;
import org.junit.jupiter.api.Test;

class AaisTest {
  private static ObjectNode fixture(String name) throws IOException{return Aais.parse(Files.readString(Path.of("..","examples",name)));}
  @Test void validatesSharedDigest()throws IOException{ObjectNode request=fixture("shell-approval.json");assertEquals(request.path("request").path("action_digest").asText(),Aais.actionDigest(request.path("request").path("action")));fixture("approve-once.json");}
  @Test void canonicalizesKeyOrder()throws Exception{assertEquals(Aais.actionDigest(Aais.JSON.readTree("{\"b\":2,\"a\":1}")),Aais.actionDigest(Aais.JSON.readTree("{\"a\":1,\"b\":2}")));}
  @Test void approvesReplaysAndRejectsConflict()throws IOException{ApprovalStore store=new ApprovalStore();store.add(fixture("shell-approval.json"));ObjectNode decision=fixture("approve-once.json");OffsetDateTime at=OffsetDateTime.parse("2026-08-30T18:01:00Z");ObjectNode first=store.decide(decision,at,null);assertEquals("approved",first.path("resolution").path("outcome").asText());assertEquals(first,store.decide(decision,at,null));ObjectNode changed=decision.deepCopy();((ObjectNode)changed.path("decision")).put("id","dec_other").put("decision","deny");assertThrows(AaisException.class,()->store.decide(changed,at,null));}
  @Test void expiresAndRejectsUnofferedScope()throws IOException{ApprovalStore expired=new ApprovalStore();expired.add(fixture("shell-approval.json"));assertEquals("expired",expired.decide(fixture("approve-once.json"),OffsetDateTime.parse("2026-08-30T19:00:00Z"),null).path("resolution").path("outcome").asText());ApprovalStore store=new ApprovalStore();store.add(fixture("shell-approval.json"));ObjectNode decision=fixture("approve-once.json");((ObjectNode)decision.path("decision")).put("scope","persistent");assertEquals("invalid",store.decide(decision,OffsetDateTime.parse("2026-08-30T18:01:00Z"),null).path("resolution").path("outcome").asText());}
  @Test void snapshotIsValid()throws IOException{ApprovalStore store=new ApprovalStore();store.add(fixture("shell-approval.json"));OffsetDateTime at=OffsetDateTime.parse("2026-08-30T18:01:00Z");ObjectNode snapshot=store.snapshot("session_s1",at);assertEquals(1,snapshot.path("snapshot").path("pending").size());Aais.validate(snapshot);assertEquals(1,ApprovalStore.fromSnapshot(snapshot).snapshot(null,at).path("snapshot").path("pending").size());}
  @Test void buildersAreValid()throws IOException{ObjectNode source=fixture("shell-approval.json");OffsetDateTime at=OffsetDateTime.parse("2026-08-30T18:00:00Z");ObjectNode request=Aais.createRequest((ObjectNode)source.path("request").path("action"),(ObjectNode)source.path("request").path("origin"),(ObjectNode)source.path("request").path("risk"),(com.fasterxml.jackson.databind.node.ArrayNode)source.path("request").path("choices"),1,"session",at,at.plusMinutes(10));ObjectNode actor=Aais.JSON.createObjectNode().put("id","alex").put("type","human");Aais.validate(Aais.createDecision(request,"approve","once",actor,2,at.plusMinutes(1),null));}
}
