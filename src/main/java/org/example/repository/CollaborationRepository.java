package org.example.repository;

import org.example.entities.Collaboration;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface CollaborationRepository extends JpaRepository<Collaboration, Long> {
    List<Collaboration> findByNoteId(Long noteId);
    List<Collaboration> findByFolderId(Long folderId);
    List<Collaboration> findByUserId(Long userId);
    List<Collaboration> findByUserIdAndFolderId(Long userId, Long folderId); // Add this method
    List<Collaboration> findByUserIdAndStatus(Long userId, Collaboration.CollaborationStatus status);
    List<Collaboration> findByUserIdAndNoteId(Long userId, Long noteId);

}