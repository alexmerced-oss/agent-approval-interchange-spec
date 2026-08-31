package io.github.alexmercedcoder.aais;

/** Base runtime exception for invalid AAIS documents and transitions. */
public class AaisException extends RuntimeException {
  private static final long serialVersionUID = 1L;
  /** Create an AAIS exception.
   * @param message safe diagnostic
   */
  public AaisException(String message) { super(message); }
  /** Create an AAIS exception with a cause.
   * @param message safe diagnostic
   * @param cause underlying failure
   */
  public AaisException(String message, Throwable cause) { super(message, cause); }
}
