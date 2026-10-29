import { useEffect, useRef } from "react";
import type { ModuleData } from "../lib/data";
import { SphereScene, type Relations, type Theme } from "../lib/sphere";

type Props = {
  modules: ModuleData[];
  active: number;
  selected: number[];
  theme: Theme;
  relations: Relations | null;
  breakpoints: Record<string, Set<number>>;
  progress: { percent: number } | null;
  rotateTo: number | null;
  compact: boolean;
  flash: { i: number; seq: number } | null;
  pulseKey: number;
};

/** 球体画布：拖拽旋转；选中由函数列表驱动，球负责转到目标正面。 */
export function SphereCanvas({ modules, active, selected, theme, relations, breakpoints, progress, rotateTo, compact, flash, pulseKey }: Props) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const sceneRef = useRef<SphereScene | null>(null);

  useEffect(() => {
    const cv = canvasRef.current;
    if (!cv) return;
    const s = new SphereScene(cv);
    sceneRef.current = s;
    s.resize();
    s.start();
    const ro = new ResizeObserver(() => s.resize());
    ro.observe(cv);

    let dragging = false, lx = 0, ly = 0;
    const down = (e: PointerEvent) => {
      dragging = true; lx = e.clientX; ly = e.clientY;
      cv.setPointerCapture(e.pointerId);
      cv.style.cursor = "grabbing";
    };
    const move = (e: PointerEvent) => {
      if (!dragging) return;
      s.dragBy(e.clientX - lx, e.clientY - ly);
      lx = e.clientX; ly = e.clientY;
    };
    const up = () => { dragging = false; cv.style.cursor = "grab"; };
    const hover = (e: PointerEvent) => {
      if (dragging) return;
      const box = cv.getBoundingClientRect();
      s.setMouse(e.clientX - box.left, e.clientY - box.top);
    };
    const leave = () => s.setMouse(-1, -1);
    cv.addEventListener("pointerdown", down);
    cv.addEventListener("pointermove", move);
    cv.addEventListener("pointerup", up);
    cv.addEventListener("pointercancel", up);
    cv.addEventListener("pointermove", hover);
    cv.addEventListener("pointerleave", leave);
    cv.style.cursor = "grab";
    return () => {
      ro.disconnect();
      cv.removeEventListener("pointerdown", down);
      cv.removeEventListener("pointermove", move);
      cv.removeEventListener("pointerup", up);
      cv.removeEventListener("pointercancel", up);
      cv.removeEventListener("pointermove", hover);
      cv.removeEventListener("pointerleave", leave);
      s.stop();
    };
  }, []);

  useEffect(() => {
    sceneRef.current?.setModules(modules);
  }, [modules]);

  useEffect(() => {
    sceneRef.current?.setActive(active);
  }, [active]);

  useEffect(() => {
    sceneRef.current?.setSelected(selected);
  }, [selected]);

  useEffect(() => {
    sceneRef.current?.setRelations(relations);
  }, [relations]);

  useEffect(() => {
    sceneRef.current?.setBreakpoints(breakpoints);
  }, [breakpoints]);

  useEffect(() => {
    sceneRef.current?.setProgress(progress);
  }, [progress]);

  useEffect(() => {
    if (rotateTo !== null && rotateTo >= 0) sceneRef.current?.rotateTo(rotateTo);
  }, [rotateTo]);

  useEffect(() => {
    if (sceneRef.current) sceneRef.current.theme = theme;
  }, [theme]);

  useEffect(() => {
    if (flash && flash.i >= 0) sceneRef.current?.setFlash(flash.i);
  }, [flash]);

  useEffect(() => {
    if (pulseKey > 0) sceneRef.current?.pulse();
  }, [pulseKey]);

  useEffect(() => {
    sceneRef.current?.setCompact(compact);
    const cv = canvasRef.current;
    if (cv) cv.style.pointerEvents = compact ? "none" : "auto";
  }, [compact]);

  return <canvas ref={canvasRef} />;
}
