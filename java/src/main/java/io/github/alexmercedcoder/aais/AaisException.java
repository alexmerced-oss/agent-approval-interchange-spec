package io.github.alexmercedcoder.aais;

/** Base runtime exception for invalid AAIS documents and transitions. */
public class AaisException extends RuntimeException {
  private static final long serialVersionUID = 1L;
  public AaisException(String message) { super(message); }
  public AaisException(String message, Throwable cause) { super(message, cause); }
}
