declare module 'cytoscape' {
  interface ElementDefinition {
    data: Record<string, unknown>;
  }

  interface CytoscapeStyle {
    selector: string;
    style: Record<string, unknown>;
  }

  interface LayoutOptions {
    name: string;
    animate?: boolean;
    animationDuration?: number;
    [key: string]: unknown;
  }

  interface Core {
    destroy(): void;
  }

  interface CytoscapeOptions {
    container?: HTMLElement;
    elements?: ElementDefinition[];
    style?: CytoscapeStyle[];
    layout?: LayoutOptions;
  }

  function cytoscape(options?: CytoscapeOptions): Core;
  export = cytoscape;
}
