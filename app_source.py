"""Applications v2: the source repository of a demo app, rendered from its BOM.

Each app with a "repo" in app-data/bom/ gets a small Maven project in the lab Gitea, so a fix can also be tested the
long way: clone, set the new versions in pom.xml, mvn package, run. The project is the same app the sites run:
  pom.xml                           the BOM's Maven dependencies at their versions; copy-dependencies to target/lib
  src/main/java/HealthServer.java   the file the sites run (aap-setup/playbooks/files/HealthServer.java)
  src/main/java/Uses.java           one reference per library to a real class in it, so a version that removes it
                                    fails the build: compiling is the point of this path
  README.md

aap-setup/create-app-v2-objects.py --seed-repos commits these files to Gitea; the tests check them.
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
GROUP = 'com.lab.appv2'


def maven_deps(bom: dict) -> list[dict]:
    return [d for d in bom.get('dependencies', []) if d.get('ecosystem', 'maven') == 'maven']


def pom_xml(bom: dict) -> str:
    deps = '\n'.join(f"""    <dependency>
      <groupId>{d['group']}</groupId>
      <artifactId>{d['artifact']}</artifactId>
      <version>{d['version']}</version>
    </dependency>""" for d in maven_deps(bom))
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!-- {bom['app']}: an Applications v2 demo app. Its dependencies are the ones in app-data/bom/{bom['app']}.json. -->
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>
  <groupId>{GROUP}</groupId>
  <artifactId>{bom['app']}</artifactId>
  <version>1.0.0</version>
  <packaging>jar</packaging>
  <name>{bom['app']} ({bom.get('domain', '')})</name>

  <properties>
    <maven.compiler.release>17</maven.compiler.release>
    <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
  </properties>

  <dependencies>
{deps}
  </dependencies>

  <build>
    <finalName>{bom['app']}</finalName>
    <plugins>
      <plugin>
        <groupId>org.apache.maven.plugins</groupId>
        <artifactId>maven-dependency-plugin</artifactId>
        <version>3.6.1</version>
        <executions>
          <execution>
            <id>copy-dependencies</id>
            <phase>package</phase>
            <goals><goal>copy-dependencies</goal></goals>
            <configuration>
              <outputDirectory>${{project.build.directory}}/lib</outputDirectory>
              <includeScope>runtime</includeScope>
            </configuration>
          </execution>
        </executions>
      </plugin>
    </plugins>
  </build>
</project>
"""


def uses_java(bom: dict, probes: dict[str, str]) -> str:
    refs = '\n'.join(f'        {probes[d["artifact"]]}.class,   // {d["group"]}:{d["artifact"]} {d["version"]}'
                     for d in maven_deps(bom) if d['artifact'] in probes)
    return f"""// One real class from each library {bom['app']} depends on. Referencing them makes the compiler check every
// library: a new version that drops or renames one of these fails mvn package, before anything reaches a site.
public final class Uses {{
    static final Class<?>[] LIBRARIES = {{
{refs}
    }};

    private Uses() {{}}
}}
"""


def readme(bom: dict) -> str:
    sites = ', '.join(f"{s.get('site', s['host'])} ({s['host']})" for s in bom.get('servers', [])) or 'none'
    return f"""# {bom['app']}

An Applications v2 demo app ({bom.get('domain', '')}). Sites: {sites}.

`HealthServer.java` serves `/health`, naming the jar each library is loaded from. `Uses.java` references one class
per library so a version that breaks its API fails the build. The dependencies follow
`app-data/bom/{bom['app']}.json` in the agentic patching repository.

Branches named `fix/<run>` are pushed by the console's "Rebuild from source" runs: the pom.xml change that was
built, tested in a pod and deployed. Nothing is merged automatically.
"""


def render(bom: dict, probes: dict[str, str]) -> dict[str, str]:
    """{path: content} for the app's repository."""
    return {
        'pom.xml': pom_xml(bom),
        'src/main/java/HealthServer.java': (ROOT / 'aap-setup' / 'playbooks' / 'files' / 'HealthServer.java').read_text(),
        'src/main/java/Uses.java': uses_java(bom, probes),
        'README.md': readme(bom),
    }


def repo_apps(bom_dir: Path | None = None) -> list[dict]:
    """The BOMs that name a repository and have Maven dependencies."""
    folder = bom_dir or (ROOT / 'app-data' / 'bom')
    out = []
    for f in sorted(folder.glob('*.json')):
        bom = json.loads(f.read_text())
        if bom.get('repo') and maven_deps(bom):
            out.append(bom)
    return out
