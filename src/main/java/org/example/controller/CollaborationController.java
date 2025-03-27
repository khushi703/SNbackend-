package org.example.controller;

import org.example.dto.CollaborationDTO;
import org.example.entities.Collaboration;
import org.example.service.CollaborationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/collaborations")
public class CollaborationController {
    @Autowired
    private CollaborationService collaborationService;
    @PostMapping("/share")
    public ResponseEntity<CollaborationDTO> shareNoteOrFolder(@RequestBody CollaborationDTO collaborationDTO) {
        Collaboration savedCollaboration = collaborationService.addCollaboration(collaborationDTO);
        return ResponseEntity.ok(convertToDTO(savedCollaboration));
    }

    @GetMapping("/note/{noteId}")
    public ResponseEntity<List<CollaborationDTO>> getNoteCollaborations(@PathVariable Long noteId) {
        List<Collaboration> collaborations = collaborationService.getCollaboratorsByNote(noteId);
        return ResponseEntity.ok(collaborations.stream().map(this::convertToDTO).toList());
    }

    @GetMapping("/folder/{folderId}")
    public ResponseEntity<List<CollaborationDTO>> getFolderCollaborations(@PathVariable Long folderId) {
        List<Collaboration> collaborations = collaborationService.getCollaboratorsByFolder(folderId);
        return ResponseEntity.ok(collaborations.stream().map(this::convertToDTO).toList());
    }

    @PostMapping("/accept/{collaborationId}")
    public ResponseEntity<CollaborationDTO> acceptCollaboration(@PathVariable Long collaborationId) {
        Collaboration collaboration = collaborationService.acceptCollaboration(collaborationId);
        return ResponseEntity.ok(convertToDTO(collaboration));
    }

    @PostMapping("/reject/{collaborationId}")
    public ResponseEntity<CollaborationDTO> rejectCollaboration(@PathVariable Long collaborationId) {
        Collaboration collaboration = collaborationService.rejectCollaboration(collaborationId);
        return ResponseEntity.ok(convertToDTO(collaboration));
    }

    private CollaborationDTO convertToDTO(Collaboration collaboration) {
        return new CollaborationDTO(
                collaboration.getCollaborationId(),
                collaboration.getUser().getId(),
                collaboration.getNote() != null ? collaboration.getNote().getId() : null,
                collaboration.getFolder() != null ? collaboration.getFolder().getId() : null,
                collaboration.getInvitedAt(),
                collaboration.getStatus() == Collaboration.CollaborationStatus.ACCEPTED,
                collaboration.getRole(),
                collaboration.getStatus()
        );
    }


    @GetMapping("/note-permission/{userId}/{noteId}/{role}")
    public ResponseEntity<Boolean> hasNotePermission(
            @PathVariable Long userId,
            @PathVariable Long noteId,
            @PathVariable Collaboration.CollaborationRole role
    ) {
        return ResponseEntity.ok(collaborationService.hasNotePermission(userId, noteId, role));
    }
    @GetMapping("/folder-permission/{userId}/{folderId}/{role}")
    public ResponseEntity<Boolean> hasFolderPermission(@PathVariable Long userId, @PathVariable Long folderId, @PathVariable Collaboration.CollaborationRole role) {
        return ResponseEntity.ok(collaborationService.hasNotePermission(userId, folderId, role));
    }
}