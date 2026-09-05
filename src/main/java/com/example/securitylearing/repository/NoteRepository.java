package com.example.securitylearing.repository;

import com.example.securitylearing.entity.Note;
import org.springframework.data.jpa.repository.JpaRepository;

public interface NoteRepository extends JpaRepository<Note,Long> {
  
}
