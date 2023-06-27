package supplementarysanity

const (
	// AppID is the unique application identifier.
	// This application isn't enabled in the production configuration,
	// so no need to reserve a low sequential identifier.
	AppID uint8 = 0x98

	// AppName is the ABCI application name.
	AppName string = "999_supplementarysanity"
)
