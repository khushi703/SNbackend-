package org.example.repository;
import org.example.entities.Note;
import org.example.entities.User;
import org.example.entities.Folder;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface NoteRepository extends JpaRepository<Note, Long> {
    List<Note> findByOwner(User owner);
    List<Note> findByFolder(Folder folder);
}
