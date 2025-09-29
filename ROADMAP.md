# TRACER Framework Development Roadmap

> **Status**: Work in Progress
> **Vision**: Evolve TRACER from CLI tool to enterprise-ready network forensics platform while maintaining simplicity for small security teams

## Current State (v0.1)

🧪 **CLI Tool - Beta Testing Phase**
- Interactive network path analysis
- JSON-based case persistence
- Real-time logging
- Case continuation and viewing
- Pivot point analysis for lateral movement

**Current Focus**: Working through test cases and validation scenarios

### Testing & Feedback Phase

We're actively testing the CLI tool with various network forensics scenarios and need community input:

**What We Need**:
- **Bug Reports**: Edge cases that break the tool or produce unexpected results
- **Workflow Feedback**: Does the enrichment process match real-world analysis patterns?
- **Use Case Validation**: Testing with different attack types (C2, data exfiltration, lateral movement)
- **Environment Testing**: Various network topologies, device types, and logging formats
- **Documentation Gaps**: Where do new users get stuck or confused?

**How to Contribute Feedback**:
- Submit issues at: https://github.com/steveinit/TRACER-framework/issues
- Include case details, expected vs actual behavior
- Share anonymized network path examples
- Suggest workflow improvements

**Known Areas for Testing**:
- Complex pivot scenarios with multiple lateral movements
- Large enterprise network paths (10+ network elements)
- Integration with existing SOC documentation workflows
- Data export/import between team members

## Future Vision (Phases likely to change)

### Phase 1: CLI Stabilization
- Modularize code: I'm a network security dude doing my best. I know Tracer is currently monolithic. We gotta break it down into functional components, so that's the current focus.
- Address critical bugs and feedback from testing phase (please break it and tell us)
- documentation (yay)

### Phase 2: API Backend
- REST API wrapping the CLI engine
- Enable SIEM/SOAR integration
- Enable NDR Integration
- Multi-user capabilities

### Phase 3: Web Interface
- Browser-based UI for team collaboration
- Visual network path diagrams
- Case management dashboard

## Timeline

**Beta Testing & Feedback**: Ongoing
**Phase 1**: After testing complete
**Phase 2**: TBD
**Phase 3**: TBD

## Contributing

This roadmap represents the evolution plan for TRACER. We welcome:
- **Testing feedback**: Real-world usage scenarios and edge cases
- **Architecture input**: High-level design suggestions
- **Use case validation**: Does this meet your network forensics needs?

---

> **Remember**: The CLI tool is functional (unless you break it) today for network forensics. This roadmap is about adding enterprise capabilities while keeping the core simple and reliable.