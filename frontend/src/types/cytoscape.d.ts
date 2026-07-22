declare module 'cytoscape' {
  interface ElementDefinition {
    data: Record<string, any>;
  }

  interface CytoscapeStyle {
    selector: string;
    style: Record<string, any>;
  }

  interface LayoutOptions {
    name: string;
    animate?: boolean;
    animationDuration?: number;
    [key: string]: any;
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
