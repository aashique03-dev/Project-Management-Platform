import { useEffect, useState } from "react";

export default function CursorGlow() {
  const [position, setPosition] = useState({ x: 0, y: 0 });

  useEffect(() => {
    const moveCursor = (e) => {
      setPosition({ x: e.clientX, y: e.clientY });
    };

    window.addEventListener("mousemove", moveCursor);
    return () => window.removeEventListener("mousemove", moveCursor);
  }, []);

  return (
    <div
      style={{
        position: "fixed",
        top: position.y - 15, // center the circle
        left: position.x - 15,
        width: "30px",
        height: "30px",
        borderRadius: "50%",
        pointerEvents: "none",
        zIndex: 9999,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        backgroundColor: "transparent",
        border: "2px solid rgba(245,158,11,0.3)", // transparent circle line
        boxShadow: "0 0 10px rgba(245,158,11,0.2), 0 0 20px rgba(245,158,11,0.15)",
        transition: "transform 0.1s ease-out",
      }}
    >
      {/* Inner dot */}
      <div
        style={{
          width: "8px",
          height: "8px",
          borderRadius: "50%",
          backgroundColor: "#F59E0B", // solid dot
        }}
      />
    </div>
  );
}