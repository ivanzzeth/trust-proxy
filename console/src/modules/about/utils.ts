type VersionData = {
  version?: string;
  premium?: boolean;
  meta?: boolean;
};

export function getCoreVersionMeta(version?: VersionData) {
  if (!version?.version) {
    return null;
  }

  if (version.meta && version.premium) {
    return {
      name: 'sing-box',
      link: 'https://github.com/SagerNet/sing-box',
    };
  }

  if (version.meta) {
    return {
      name: 'Clash.Meta',
      link: 'https://github.com/MetaCubeX/Clash.Meta',
    };
  }

  return {
    name: 'Clash',
    link: 'https://github.com/Dreamacro/clash',
  };
}
