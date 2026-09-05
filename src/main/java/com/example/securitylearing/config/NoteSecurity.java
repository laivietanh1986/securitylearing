package com.example.securitylearing.config;

import com.example.securitylearing.repository.NoteRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component("noteSecurity")
@RequiredArgsConstructor
public class NoteSecurity {

  private final NoteRepository noteRepository;

  public boolean isOwner(Long noteId, String username) {
    return noteRepository.findById(noteId)
        .map(note -> note.getOwner().equals(username))
        .orElse(false);
  }
}
